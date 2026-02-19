// Required to run `npm run dev`.
if (!window.global) {
    window.global = window;
}

import "./style.css";
import { createActor } from "./declarations/basic_timelock_ibe";
import { Principal } from "@dfinity/principal";
import {
    DerivedPublicKey,
    IbeCiphertext,
    IbeIdentity,
    IbeSeed,
} from "@dfinity/vetkeys";
import {
    _SERVICE,
    LotInformation,
} from "./declarations/basic_timelock_ibe/basic_timelock_ibe.did";
import { AuthClient } from "@dfinity/auth-client";
import type { ActorSubclass } from "@dfinity/agent";

let ibePublicKey: DerivedPublicKey | undefined = undefined;
let myPrincipal: Principal | undefined = undefined;
let authClient: AuthClient | undefined;
let basicTimelockIbeCanister: ActorSubclass<_SERVICE> | undefined;

function getBasicTimelockIbeCanister(): ActorSubclass<_SERVICE> {
    if (basicTimelockIbeCanister) return basicTimelockIbeCanister;
    if (!process.env.CANISTER_ID_BASIC_TIMELOCK_IBE) {
        throw Error("CANISTER_ID_BASIC_TIMELOCK_IBE is not set");
    }
    if (!authClient) {
        throw Error("Auth client is not initialized");
    }
    const host =
        process.env.DFX_NETWORK === "ic"
            ? `https://${process.env.CANISTER_ID_BASIC_TIMELOCK_IBE}.ic0.app`
            : "http://localhost:8000";

    basicTimelockIbeCanister = createActor(
        process.env.CANISTER_ID_BASIC_TIMELOCK_IBE,
        {
            agentOptions: {
                identity: authClient.getIdentity(),
                host,
            },
        },
    );

    return basicTimelockIbeCanister;
}

export function login(client: AuthClient) {
    void client.login({
        maxTimeToLive: BigInt(1800) * BigInt(1_000_000_000),
        identityProvider:
            process.env.DFX_NETWORK === "ic"
                ? "https://identity.ic0.app/#authorize"
                : `http://rdmx6-jaaaa-aaaaa-aaadq-cai.localhost:8000/#authorize`,
        onSuccess: () => {
            myPrincipal = client.getIdentity().getPrincipal();
            updateUI(true);
        },
        onError: (error) => {
            alert("Authentication failed: " + error);
        },
    });
}

export function logout() {
    void authClient?.logout();
    myPrincipal = undefined;
    basicTimelockIbeCanister = undefined;
    updateUI(false);

    // Reset the lots list and form visibility
    document.getElementById("lotsList")!.classList.toggle("hidden", true);
    document.getElementById("lotForm")!.classList.toggle("hidden", true);
}

async function initAuth() {
    authClient = await AuthClient.create();
    const isAuthenticated = await authClient.isAuthenticated();

    if (isAuthenticated) {
        myPrincipal = authClient.getIdentity().getPrincipal();
        updateUI(true);
    } else {
        updateUI(false);
    }
}

function updateUI(isAuthenticated: boolean) {
    const loginButton = document.getElementById("loginButton")!;
    const principalDisplay = document.getElementById("principalDisplay")!;
    const logoutButton = document.getElementById("logoutButton")!;
    const lotActions = document.getElementById("lotActions")!;
    const lotForm = document.getElementById("lotForm")!;
    const lotsList = document.getElementById("lotsList")!;

    loginButton.classList.toggle("hidden", isAuthenticated);
    principalDisplay.classList.toggle("hidden", !isAuthenticated);
    logoutButton.classList.toggle("hidden", !isAuthenticated);
    lotActions.classList.toggle("hidden", !isAuthenticated);
    lotForm.classList.toggle("hidden", true);
    lotsList.classList.toggle("hidden", true);

    if (isAuthenticated && myPrincipal) {
        principalDisplay.textContent = `Principal: ${myPrincipal.toString()}`;
    }
}

function handleLogin() {
    if (!authClient) {
        alert("Auth client not initialized");
        return;
    }

    login(authClient);
}

document.querySelector<HTMLDivElement>("#app")!.innerHTML = `
  <div>
    <h1>Secret Bid Auction using VetKeys (Basic Timelock IBE)</h1>
    <div class="principal-container">
      <div id="principalDisplay" class="principal-display"></div>
      <button id="logoutButton">Logout</button>
    </div>
    <div class="login-container">
      <button id="loginButton">Login</button>
    </div>
    <div id="lotActions" class="buttons">
      <button id="createLotButton">Create New Lot</button>
      <button id="listLotsButton">List Lots</button>
    </div>
    <div id="lotForm">
      <h3>Create New Lot</h3>
      <form id="createLotForm">
        <div>
          <label for="lotName">Name</label>
          <input type="text" id="lotName" required>
        </div>
        <div>
          <label for="lotDescription">Description</label>
          <textarea id="lotDescription" required></textarea>
        </div>
        <div>
          <label for="lotDuration">Duration (seconds)</label>
          <input type="number" id="lotDuration" min="1" required>
        </div>
        <button type="submit">Submit</button>
      </form>
    </div>
    <div id="lotsList">
      <div id="openLots"></div>
      <div id="closedLots"></div>
    </div>
  </div>
`;

// Add event listeners
document.getElementById("loginButton")!.addEventListener("click", handleLogin);
document.getElementById("logoutButton")!.addEventListener("click", logout);
document.getElementById("createLotButton")!.addEventListener("click", () => {
    document.getElementById("lotForm")!.classList.toggle("hidden", false);
    document.getElementById("lotsList")!.classList.toggle("hidden", true);
});
document.getElementById("listLotsButton")!.addEventListener("click", () => {
    void (async () => {
        await listLots();
    })();
});
document.getElementById("createLotForm")!.addEventListener("submit", (e) => {
    (e as Event).preventDefault();
    const name = (document.getElementById("lotName") as HTMLInputElement).value;
    const description = (
        document.getElementById("lotDescription") as HTMLTextAreaElement
    ).value;
    const duration = parseInt(
        (document.getElementById("lotDuration") as HTMLInputElement).value,
    );
    void createLot(name, description, duration);
});

async function getIbePublicKey(): Promise<DerivedPublicKey> {
    if (ibePublicKey) return ibePublicKey;
    ibePublicKey = DerivedPublicKey.deserialize(
        new Uint8Array(
            await getBasicTimelockIbeCanister().get_ibe_public_key(),
        ),
    );
    return ibePublicKey;
}

async function encrypt(
    cleartext: Uint8Array,
    identity: Uint8Array,
): Promise<Uint8Array> {
    const publicKey = await getIbePublicKey();
    const ciphertext = IbeCiphertext.encrypt(
        publicKey,
        IbeIdentity.fromBytes(identity),
        cleartext,
        IbeSeed.random(),
    );
    return ciphertext.serialize();
}

async function createLot(
    name: string,
    description: string,
    durationSeconds: number,
) {
    const result = await getBasicTimelockIbeCanister().create_lot(
        name,
        description,
        durationSeconds,
    );
    if ("Ok" in result) {
        alert(`Lot created successfully with ID: ${result.Ok.toString()}`);
    } else {
        alert(`Failed to create lot: ${result.Err}`);
    }
    document.getElementById("lotForm")!.classList.toggle("hidden", true);
}

function getStatusForOpenLot(
    lot: LotInformation,
    bidders: Principal[],
): string {
    if (
        bidders.find(
            (bidder) => bidder.compareTo(myPrincipal as Principal) === "eq",
        )
    ) {
        return '<span class="lot-status status-placed">BID PLACED</span>';
    } else if (lot.creator.compareTo(myPrincipal as Principal) === "eq") {
        return '<span class="lot-status status-owner">OWNER</span>';
    }
    return "";
}

function getStatusForClosedLot(
    lot: LotInformation,
    bids: [Principal, bigint][],
): string {
    const myBid = bids.find(
        (bid) => bid[0].compareTo(myPrincipal as Principal) === "eq",
    );
    const isCreator = lot.creator.compareTo(myPrincipal as Principal) === "eq";

    if (isCreator) {
        return '<span class="lot-status status-owner">OWNER</span>';
    }

    if ("ClosedWithWinner" in lot.status) {
        if (
            lot.status.ClosedWithWinner.compareTo(myPrincipal as Principal) ===
            "eq"
        ) {
            return '<span class="lot-status status-won">WON</span>';
        } else if (myBid) {
            return '<span class="lot-status status-lost">LOST</span>';
        } else {
            return '<span class="lot-status status-skipped">SKIPPED</span>';
        }
    } else {
        return '<span class="lot-status status-skipped">SKIPPED</span>';
    }
}

function formatPrincipal(
    principal: Principal,
    isWinner: boolean = false,
): string {
    const classes = [];
    if (isWinner) classes.push("principal-winner");
    if (myPrincipal && principal.compareTo(myPrincipal) === "eq")
        classes.push("principal-me");
    return `<span class="principal-indicator ${classes.join(" ")}">${principal.toString()}</span>`;
}

function formatCountdown(endTime: bigint): string {
    const now = BigInt(Date.now() * 1_000_000);
    const remaining = endTime - now;

    if (remaining <= 0n) {
        return '<span class="lot-countdown">Ended</span>';
    }

    const seconds = Number(remaining / 1_000_000_000n);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    const remainingHours = hours % 24;
    const remainingMinutes = minutes % 60;
    const remainingSeconds = seconds % 60;

    return `<span class="lot-countdown">${days}d ${remainingHours}h ${remainingMinutes}m ${remainingSeconds}s</span>`;
}

async function listLots() {
    try {
        const [openLots, closedLots] =
            await getBasicTimelockIbeCanister().get_lots();
        const openLotsDiv = document.getElementById("openLots")!;
        const closedLotsDiv = document.getElementById("closedLots")!;

        // Clear both containers first
        openLotsDiv.innerHTML = "";
        closedLotsDiv.innerHTML = "";

        if (openLots.lots.length === 0) {
            openLotsDiv.innerHTML = "<h4>Open Lots</h4><p>No open lots</p>";
        } else {
            const fragment = document.createDocumentFragment();
            const heading = document.createElement("h4");
            heading.textContent = "Open Lots";
            fragment.appendChild(heading);

            openLots.lots.reverse();
            openLots.bidders.reverse();

            openLots.lots.forEach((lot, index) => {
                const lotDiv = document.createElement("div");
                lotDiv.className = "lot";
                const isCreator =
                    lot.creator.compareTo(myPrincipal as Principal) === "eq";
                const status = getStatusForOpenLot(
                    openLots.lots[index],
                    openLots.bidders[index],
                );

                lotDiv.innerHTML = `
          <h5>Name: ${lot.name}</h5>
          <p>Description: ${lot.description}</p>
          <p>Creator: ${lot.creator.toText()}</p>
          <p>Closing in: ${formatCountdown(lot.end_time)}</p>
          ${status}
          <p>Bidders:${openLots.bidders[index].length === 0 ? " no bidders yet" : openLots.bidders[index].map((bidder) => "<br>" + formatPrincipal(bidder)).join("")}</p>
          ${
              !isCreator
                  ? `
          <form id="bidForm-${lot.id}" class="bid-form">
            <div>
              <label for="bidAmount-${lot.id}">Bid Amount:</label>
              <input type="number" id="bidAmount-${lot.id}" min="1" required>
            </div>
            <button type="submit">Place Bid</button>
          </form>
          `
                  : ""
          }
        `;

                if (!isCreator) {
                    const bidForm = lotDiv.querySelector(`#bidForm-${lot.id}`);
                    if (bidForm) {
                        bidForm.addEventListener("submit", (e) => {
                            e.preventDefault();
                            const amount = parseInt(
                                (
                                    document.getElementById(
                                        `bidAmount-${lot.id}`,
                                    ) as HTMLInputElement
                                ).value,
                            );
                            void placeBid(lot.id, amount);
                        });
                    }
                }

                fragment.appendChild(lotDiv);
            });

            openLotsDiv.innerHTML = "";
            openLotsDiv.appendChild(fragment);
        }

        if (closedLots.lots.length === 0) {
            closedLotsDiv.innerHTML =
                "<h4>Closed Lots</h4><p>No closed lots</p>";
        } else {
            const fragment = document.createDocumentFragment();
            const heading = document.createElement("h4");
            heading.textContent = "Closed Lots";
            fragment.appendChild(heading);

            closedLots.lots.reverse();
            closedLots.bids.reverse();

            closedLots.lots.forEach((lot, index) => {
                const lotDiv = document.createElement("div");
                lotDiv.className = "lot";
                const isWinner =
                    "ClosedWithWinner" in lot.status &&
                    lot.status.ClosedWithWinner.compareTo(
                        myPrincipal as Principal,
                    ) === "eq";
                const status = getStatusForClosedLot(
                    lot,
                    closedLots.bids[index],
                );

                lotDiv.innerHTML = `
          <h5>Name: ${lot.name}</h5>
          <p>Description: ${lot.description}</p>
          <p>Creator: ${formatPrincipal(lot.creator)}</p>
          <p>Winner: ${"ClosedWithWinner" in lot.status ? formatPrincipal(lot.status.ClosedWithWinner, isWinner) : "No winner"}</p>
          <p>Ended at: ${new Date(Number(lot.end_time) / 1000000).toLocaleString()}</p>
          ${status}
          <p>Bids: ${
              closedLots.bids[index].length === 0
                  ? " no bids"
                  : closedLots.bids[index]
                        .map(
                            (bid) =>
                                `<br>${formatPrincipal(
                                    bid[0],
                                    "ClosedWithWinner" in lot.status &&
                                        lot.status.ClosedWithWinner.compareTo(
                                            bid[0],
                                        ) === "eq",
                                )}: ${bid[1]}`,
                        )
                        .join("")
          }</p>
        `;

                fragment.appendChild(lotDiv);
            });

            closedLotsDiv.innerHTML = "";
            closedLotsDiv.appendChild(fragment);
        }

        document.getElementById("lotsList")!.classList.toggle("hidden", false);
    } catch (error) {
        alert(`Failed to list lots: ${error as Error}`);
    }
}

async function placeBid(lotId: bigint, amount: number) {
    try {
        const lotIdBytes = u128ToLeBytes(lotId);
        const amountBytes = u128ToLeBytes(BigInt(amount));

        // Encrypt the bid amount using IBE
        const encryptedAmount = await encrypt(amountBytes, lotIdBytes);

        // Place the bid
        const result = await getBasicTimelockIbeCanister().place_bid(
            lotId,
            encryptedAmount,
        );
        if ("Err" in result) {
            alert(`Failed to place bid: ${result.Err}`);
            return;
        }

        alert("Bid placed successfully!");
        // Refresh the lots list
        await listLots();
    } catch (error) {
        alert(`Failed to place bid: ${error as Error}`);
    }
}

function u128ToLeBytes(value: bigint): Uint8Array {
    const bytes = new Uint8Array(16);
    let temp = value;

    for (let i = 0; i < 16; i++) {
        bytes[i] = Number(temp & 0xffn);
        temp >>= 8n;
    }

    return bytes;
}

// Initialize auth
void initAuth();
