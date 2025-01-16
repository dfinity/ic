import matplotlib.pyplot as plt
from collections import Counter

def process_and_plot(data):
    """
    Process the input data, remark duplicates, and plot the graph.

    Args:
        data (list of lists): List of [l, value] pairs.
    """
    # Extract l and value
    l_values = [point[0] for point in data]
    values = [point[1] for point in data]

    # Identify duplicates using Counter
    l_counter = Counter(l_values)
    duplicates = {l: count for l, count in l_counter.items() if count > 1}

    if duplicates:
        print("Found duplicates:")
        for l, count in duplicates.items():
            print(f"l = {l} appears {count} times")
    else:
        print("No duplicates found.")

    # Create a scatter plot
    plt.figure(figsize=(10, 6))
    
    for l, value in data:
        if l in duplicates:
            # Highlight duplicate points in red
            plt.scatter(l, value, color='red', label='Duplicate' if 'Duplicate' not in plt.gca().get_legend_handles_labels()[1] else "")
        else:
            # Plot non-duplicate points in blue
            plt.scatter(l, value, color='blue', label='Unique' if 'Unique' not in plt.gca().get_legend_handles_labels()[1] else "")

    # Add labels and legend
    plt.title("Data Points with Duplicates Highlighted")
    plt.xlim(left=0)
    plt.xlabel("l")
    plt.ylabel("value")
    plt.legend()
    plt.grid(True)
    
    # Show the plot
    plt.show()

# Load data from a text file
def parse_file(filename):
    """
    Reads a file of lines in the format:
      [x, y],
      [x, y],
    and returns a list of (x, y) pairs as integers.
    """
    points = []
    with open(filename, 'r') as f:
        for line in f:
            # Example line: "[10, 1]," -> after strip: "[10, 1],"
            line = line.strip()
            
            # Ignore empty lines (if any)
            if not line:
                continue
            
            # Remove trailing commas
            line = line.rstrip(',')
            
            # Remove brackets (the first and last character if they are '[' and ']')
            # or use a regex to extract the numbers
            # For simplicity, let's just strip them:
            line = line.strip('[]')
            
            # Split on comma -> ["10", " 1"] for example
            parts = line.split(',')
            
            if len(parts) != 2:
                continue  # skip any malformed line
            
            x_str, y_str = parts
            # Convert them to integers
            x_val = int(x_str.strip())
            y_val = float(y_str.strip())
            points.append((x_val, y_val))
    return points

# File path to the input data
file_path = "debug.log"
data = parse_file(file_path)

if data:
    # Process and plot the data
    process_and_plot(data)
else:
    print("No data to process.")
