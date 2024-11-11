// This tool is a replacement for the system "restorecon" utility that
// parallelizes the label lookup (it turns out that the regex processing
// is taking majority of the CPU time, but parallelizing filesystem
// traversal certainly helps as well).
//
// Preferred usage: prestorecon -j 0 <path>
//
// This will trigger relabelling using all available CPUs.

#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <functional>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

class WorkPool {
public:
    // Empty workpool.
    inline WorkPool() {}

    bool
    empty() const noexcept
    {
        return dirs_to_visit.empty() && inodes_to_label.empty();
    }

    void
    merge(WorkPool other);

    // Take list of pathnames to initially add to the workpool. Will test
    // all input paths whether they are directories or not.
    WorkPool(const std::vector<std::string>& initial_paths);
    std::vector<std::string> dirs_to_visit;
    std::vector<std::pair<std::string, mode_t>> inodes_to_label;
};

WorkPool::WorkPool(const std::vector<std::string>& initial_paths)
{
    for (const auto& path : initial_paths) {
        // We are open-coding the system call to lstat here
        // to determine mode (permissions and file type) of path
        // in question.
        //
        // It would in principle be possible to use
        // std::filesystem::is_directory instead, but that would
        // cause an additional lstat system call internal to this
        // function to be issued (and we would really like to get
        // high throughput and minimize number of syscalls per
        // loop).
        //
        // The other alternative would be to use
        // std::filesystem::status and use its result both for
        // checking whether this is a directory and obtaining
        // file type + permissions. The small annoyance with that
        // is that the selabel_lookup API function called later
        // requires exactly the mode_t as supplied by stat for
        // its decision, so we would need to "reconstruct" it
        // from the std::filesystem::status result. That is
        // possible, but probably not any more readable than
        // working with the raw system call directly.
        struct stat statbuf;
        if (::lstat(path.c_str(), &statbuf) == 0) {
            inodes_to_label.emplace_back(path, statbuf.st_mode);
            if ((statbuf.st_mode & S_IFMT) == S_IFDIR) {
                dirs_to_visit.push_back(path);
            }
        } else {
            throw std::runtime_error("Unable to stat " + path + ":" + std::strerror(errno));
        }
    }
}

void
WorkPool::merge(WorkPool other)
{
    dirs_to_visit.insert(
        dirs_to_visit.end(),
        std::make_move_iterator(other.dirs_to_visit.begin()),
        std::make_move_iterator(other.dirs_to_visit.end()));
    inodes_to_label.insert(
        inodes_to_label.end(),
        std::make_move_iterator(other.inodes_to_label.begin()),
        std::make_move_iterator(other.inodes_to_label.end()));
}


class GlobalWorkPool {
public:
    using id_type = std::size_t;

    // Pushes some work to the workpool, making it available to
    // other threads. This returns an ID by which the published
    // work can later be retrieved again (see next function).
    id_type
    add_work(WorkPool pool);

    // Given a work pool id, try to revoke a work pool that was
    // pushed previously. The two mechanisms allow one thread
    // with too much work to make part of it "available" for other
    // threads to pick up (if they have capacity), but allows
    // to get back to the same work if it was not picked up.
    // This allows a bit better thread locality than picking up
    // some "random" work from the pool.
    WorkPool
    revoke_work(id_type id);

    // Tries to steal work from the pool.
    //
    // This call may block on the pool and will eventually return
    // with either:
    // - some work that was obtained from the global pool
    // - an empty optional, indicating that everything is idle
    //   and calling thread should quit
    //
    // This function internally accounts for the number of active
    // threads, in order to do that each thread needs to set the
    // "was_busy" flag accordingly:
    // - on first call, it needs to specify "was_busy=false". This
    //   indicates that this is a new thread that was not "seen" by
    //   the pool before
    // - on every subsequent call, it needs to specify "was_busy=true".
    //   This indicates that this is a returning thread that has been
    //   accounted for already.
    //
    // The function will return None iff:
    // - the pool is empty
    // - all threads that are accounted for are blocked inside steal_work
    //
    // This means that at the end of processing, the last thread
    // enters this function (while all other threads are blocked on this
    // function already), and then all threads receive an empty optional
    // return from this function at the same time.
    std::optional<WorkPool>
    steal_work(
        bool was_busy,
        std::size_t limit_dirs_to_visit,
        std::size_t limit_inodes_to_label);

private:
    std::condition_variable cond_;
    std::mutex mutex_;
    // All below fields guarded by mutex.
    std::map<id_type, WorkPool> pools_ __attribute__((guarded_by(mutex_)));
    id_type next_id_ __attribute__((guarded_by(mutex_))) = 0;
    std::size_t busy_count_ __attribute__((guarded_by(mutex_))) = 0;
};

GlobalWorkPool::id_type
GlobalWorkPool::add_work(WorkPool pool)
{
    std::unique_lock guard(mutex_);
    id_type id = next_id_++;
    pools_.emplace(id, std::move(pool));
    cond_.notify_all();
    return id;
}

WorkPool
GlobalWorkPool::revoke_work(id_type id)
{
    std::unique_lock guard(mutex_);
    auto i = pools_.find(id);
    if (i != pools_.end()) {
        WorkPool tmp(std::move(i->second));
        pools_.erase(i);
        return tmp;
    } else {
        return WorkPool();
    }
}

std::optional<WorkPool>
GlobalWorkPool::steal_work(
    bool was_busy,
    std::size_t limit_dirs_to_visit,
    std::size_t limit_inodes_to_label)
{
    std::unique_lock guard(mutex_);
    for (;;) {
        if (was_busy) {
            --busy_count_;
            was_busy = false;
            if (!busy_count_) {
                cond_.notify_all();
            }
        }
        // While there is no work, but some other thread is still busy, wait.
        while (pools_.empty() && busy_count_) {
            cond_.wait(guard);
        }

        WorkPool tmp;

        // Try to steal dirs_to_visit first.
        for (auto i = pools_.begin(); i != pools_.end();) {
            if (tmp.dirs_to_visit.size() >= limit_dirs_to_visit) {
                break;
            }
            auto& victim = i->second.dirs_to_visit;
            auto begin = victim.begin();
            std::size_t count = std::min(
                victim.size(),
                limit_dirs_to_visit - tmp.dirs_to_visit.size());
            tmp.dirs_to_visit.insert(tmp.dirs_to_visit.end(), std::make_move_iterator(begin), std::make_move_iterator(begin + count));
            victim.erase(begin, begin + count);
            if (victim.empty() && i->second.inodes_to_label.empty()) {
                i = pools_.erase(i);
            } else {
                ++i;
            }
        }
        if (!tmp.empty()) {
            ++busy_count_;
            return { std::move(tmp) };
        }

        // If that fails, steal inodes_to_label.
        for (auto i = pools_.begin(); i != pools_.end();) {
            if (tmp.inodes_to_label.size() >= limit_inodes_to_label) {
                break;
            }
            auto& victim = i->second.inodes_to_label;
            auto begin = victim.begin();
            std::size_t count = std::min(
                victim.size(),
                limit_dirs_to_visit - tmp.inodes_to_label.size());
            tmp.inodes_to_label.insert(tmp.inodes_to_label.end(), std::make_move_iterator(begin), std::make_move_iterator(begin + count));
            victim.erase(begin, begin + count);
            if (victim.empty() && i->second.dirs_to_visit.empty()) {
                i = pools_.erase(i);
            } else {
                ++i;
            }
        }
        if (!tmp.empty()) {
            ++busy_count_;
            return { std::move(tmp) };
        }

        // If no work there, check if some other thread is still busy and might produce
        // new work.
        if (busy_count_) {
            continue;
        }

        // All work is done, notify calling thread that it should terminate.
        return {};
    }
}



///////////////////////////////////////////////////////////////////////////////

const std::size_t LABEL_WORK_THRESHOLD = 1000;
const std::size_t DIR_VISIT_STEAL = 100;
const std::size_t LABEL_WORK_STEAL = 1000;

void parallel_work(
    GlobalWorkPool& global_pool,
    std::function<WorkPool(const std::string&)> list_dir,
    std::function<void(const std::vector<std::pair<std::string, mode_t>>&)> apply_labels)
{
    bool was_busy = false;
    WorkPool local_pool;

    for (;;) {
        // First, check if we have enough work accumulated that we should start
        // labeling.
        if (local_pool.inodes_to_label.size()  >= LABEL_WORK_THRESHOLD) {
            // Push all unvisited directories as well as excess inodes to label
            // to the global work pool. Some other thread may pick them up
            // while we are busily labeling here.
            WorkPool tmp;
            tmp.dirs_to_visit.swap(local_pool.dirs_to_visit);
            if (local_pool.inodes_to_label.size() > LABEL_WORK_THRESHOLD) {
                auto excess = local_pool.inodes_to_label.begin() + LABEL_WORK_THRESHOLD;
                auto end = local_pool.inodes_to_label.end();
                tmp.inodes_to_label.insert(
                    tmp.inodes_to_label.end(),
                    std::make_move_iterator(excess),
                    std::make_move_iterator(end));
                local_pool.inodes_to_label.erase(excess, end);
            }
            auto id = global_pool.add_work(std::move(tmp));

            apply_labels(local_pool.inodes_to_label);
            local_pool.inodes_to_label.clear();

            // Try to get the work pool we pushed above back and put it into
            // our local work pool.
            local_pool = global_pool.revoke_work(id);

            continue;
        }

        // If there is not enough labeling work, traverse directories
        // (depth-first) to generate more work.
        if (!local_pool.dirs_to_visit.empty()) {
            std::string dir = local_pool.dirs_to_visit.back();
            local_pool.dirs_to_visit.pop_back();
            local_pool.merge(list_dir(dir));
            continue;
        }

        // No directories to traverse known anymore, just apply labels to all
        // inodes known so far in order to drain the local work pool.
        apply_labels(local_pool.inodes_to_label);
        local_pool.inodes_to_label.clear();

        // Local work pool is completely empty at this point. Try to get more
        // work from global pool. Note that this will return None iff there is
        // no work left and also all other threads are idle.
        auto maybe_work = global_pool.steal_work(was_busy, DIR_VISIT_STEAL, LABEL_WORK_STEAL);
        if (maybe_work) {
            local_pool = std::move(*maybe_work);
            was_busy = true;
        } else {
            break;
        }
    }
}

////////////////////

WorkPool
list_dir(const std::string& path)
{
    WorkPool tmp;
    for (const auto& entry: std::filesystem::directory_iterator(path)) {
        const auto& path = entry.path().string();
        struct stat statbuf;
        if (lstat(path.c_str(), &statbuf) == 0) {
            tmp.inodes_to_label.emplace_back(path, statbuf.st_mode);
            if ((statbuf.st_mode & S_IFMT) == S_IFDIR) {
                tmp.dirs_to_visit.push_back(path);
            }
        } else {
            throw std::runtime_error("Unable to stat " + path + ":" + std::strerror(errno));
        }
    }
    return tmp;
}

#include <selinux/selinux.h>
#include <selinux/label.h>

struct relabel_stats {
    std::size_t inodes_processed = 0;
    std::size_t inodes_relabeled = 0;
};

void apply_labels(
    const std::vector<std::pair<std::string, mode_t>>& paths,
    selabel_handle* hdl, int verbosity, bool dry_run, relabel_stats& stats)
{
    for (const auto& entry : paths) {
        const auto& [path, mode] = entry;

        char* should_context;
        if (::selabel_lookup(hdl, &should_context, path.c_str(), mode)) {
            throw std::runtime_error("selabel_lookup failed for " + path + ":" + std::strerror(errno));
        }
        // Note that "should_context" cannot be null at this point (we would
        // have thrown an exception instead).

        stats.inodes_processed += 1;

        // Get present context of the file, or null pointer if no
        // context assigned to file at present.
        // The API is defined that it will return an malloc'ed c-style
        // string representing the context, so no std::string here.
        char* is_context = 0;
        if (::lgetfilecon(path.c_str(), &is_context) < 0) {
            is_context = 0;
        }

        // Need to update context if no context set or context is wrong.
        bool need_set_context = !is_context || (std::strcmp(is_context, should_context) != 0);

        // Apply context change (unless in dry-run mode).
        if (need_set_context) {
            stats.inodes_relabeled += 1;
        }
        if (need_set_context && !dry_run) {
            if (::lsetfilecon(path.c_str(), should_context)) {
                throw std::runtime_error("Unable to set context for " + path + ":" + std::strerror(errno));
            }
        }

        // Produce informative output, dependent on verbosity level.
        if (verbosity == 1) {
            if (need_set_context) {
                std::cout
                    << "Change context for " << path
                    << " from " << (is_context ? is_context : "NONE")
                    << " to " << should_context << "\n";
            }
        } else if (verbosity >= 2) {
            std::cout
                << "Context for " << path
                << " was " << (is_context ? is_context : "NONE")
                << " new " << should_context << "\n";
        }

        ::freecon(should_context);
        // Note that freecon happily accepts a null pointer and then does nothing.
        ::freecon(is_context);
    }
}

struct parsed_args {
    std::vector<std::string> paths;
    std::size_t jobs = 1;
    int verbosity = 0;
    bool dry_run = false;
};

parsed_args
parse_args(int argc, char** argv)
{
    parsed_args result;
    static const struct option long_options[] = {
        {"jobs", required_argument, nullptr, 'j'},
        {"verbose", no_argument, nullptr, 'v'},
        {"dry-run", no_argument, nullptr, 'n'},
        {nullptr, 0, nullptr, 0}
    };

    for (;;) {
        int opt = getopt_long(argc, argv, "nvj:", long_options, nullptr);
        if (opt == -1) {
            break;
        }
        switch (opt) {
            case 'j': {
                result.jobs = atoi(optarg);
                break;
            }
            case 'v': {
                result.verbosity += 1;
                break;
            }
            case 'n': {
                result.dry_run = true;
                break;
            }
        }
    }
    for (int n = optind ; n < argc; ++n) {
        result.paths.push_back(std::filesystem::absolute(argv[n]).string());
    }

    // Special case: if caller specified "0" as number of CPUs to use,
    // use all available ones.
    if (result.jobs == 0) {
        result.jobs = sysconf(_SC_NPROCESSORS_ONLN);
    }

    return result;
}

int main(int argc, char** argv)
{
    auto args = parse_args(argc, argv);

    GlobalWorkPool global_pool;
    global_pool.add_work(WorkPool(args.paths));

    std::vector<std::thread> threads;
    std::vector<relabel_stats> stats(args.jobs);
    for (std::size_t n = 0; n < args.jobs; ++n) {
        threads.emplace_back(
            [&global_pool, &args, &stats, n] () {
                auto hdl = selabel_open(SELABEL_CTX_FILE, nullptr ,0);
                parallel_work(
                    global_pool,
                    list_dir,
                    [hdl, &args, &stats, n] (const std::vector<std::pair<std::string, mode_t>>& paths) {
                        apply_labels(paths, hdl, args.verbosity, args.dry_run, stats[n]);
                    });
                selabel_close(hdl);
            }
        );
    }

    relabel_stats global_stats;

    for (std::size_t n = 0; n < args.jobs; ++n) {
        threads[n].join();
        global_stats.inodes_processed += stats[n].inodes_processed;
        global_stats.inodes_relabeled += stats[n].inodes_relabeled;
    }

    std::cout << "Processed: " << global_stats.inodes_processed << " Relabeled: " << global_stats.inodes_relabeled << "\n";

    return 0;
}
