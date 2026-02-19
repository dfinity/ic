// Required to run `npm run dev`.
if (!window.global) {
  window.global = window;
}

import "./style.css";
import { createActor } from "./declarations/basic_bls_signing";
import { Principal } from "@dfinity/principal";
import { AuthClient } from "@dfinity/auth-client";
import type { ActorSubclass } from "@dfinity/agent";
import { _SERVICE } from "./declarations/basic_bls_signing/basic_bls_signing.did";
import { DerivedPublicKey, verifyBlsSignature } from "@dfinity/vetkeys";
import type { Signature } from "./declarations/basic_bls_signing/basic_bls_signing.did";

let myPrincipal: Principal | undefined = undefined;
let authClient: AuthClient | undefined;
let basicBlsSigningCanister: ActorSubclass<_SERVICE> | undefined;
// let canisterPublicKey: DerivedPublicKey | undefined;
let myVerificationKey: DerivedPublicKey | undefined;

function getBasicBlsSigningCanister(): ActorSubclass<_SERVICE> {
  if (basicBlsSigningCanister) return basicBlsSigningCanister;
  if (!process.env.CANISTER_ID_BASIC_BLS_SIGNING) {
    throw Error("CANISTER_ID_BASIC_BLS_SIGNING is not set");
  }
  if (!authClient) {
    throw Error("Auth client is not initialized");
  }
  const host =
    process.env.DFX_NETWORK === "ic"
      ? `https://${process.env.CANISTER_ID_BASIC_BLS_SIGNING}.ic0.app`
      : "http://localhost:8000";

  basicBlsSigningCanister = createActor(
    process.env.CANISTER_ID_BASIC_BLS_SIGNING,
    {
      agentOptions: {
        identity: authClient.getIdentity(),
        host,
      },
    },
  );

  return basicBlsSigningCanister;
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
  myVerificationKey = undefined;
  basicBlsSigningCanister = undefined;
  updateUI(false);
  document.getElementById("signaturesList")!.classList.toggle("hidden", true);
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
  const signingActions = document.getElementById("signingActions")!;
  const customSignatureForm = document.getElementById("customSignatureForm")!;
  const signaturesList = document.getElementById("signaturesList")!;

  loginButton.classList.toggle("hidden", isAuthenticated);
  principalDisplay.classList.toggle("hidden", !isAuthenticated);
  logoutButton.classList.toggle("hidden", !isAuthenticated);
  signingActions.classList.toggle("hidden", !isAuthenticated);
  customSignatureForm.classList.toggle("hidden", true);
  signaturesList.classList.toggle("hidden", true);

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
    <h1>Basic BLS Signing using VetKeys</h1>
    <div class="principal-container">
      <div id="principalDisplay" class="principal-display"></div>
      <button id="logoutButton">Logout</button>
    </div>
    <div class="login-container">
      <button id="loginButton">Login</button>
    </div>
    <div id="signingActions" class="buttons">
      <button id="signMessageButton">Sign Message</button>
      <button id="listSignaturesButton">List Signatures</button>
      <button id="customSignatureButton">Verify Custom Signature</button>
    </div>
    <div id="customSignatureForm">
      <h3>Verify Custom Signature</h3>
      <form id="submitSignatureForm">
        <div>
          <label for="message">Message</label>
          <input type="text" id="message" required>
        </div>
        <div>
          <label for="signature">Signature (hex)</label>
          <input type="text" id="signature" required>
        </div>
        <div>
          <label for="pubkey">Public key (hex)</label>
          <input type="text" id="pubkey" required>
        </div>
        <button type="submit">Submit</button>
      </form>
    </div>
    <div id="signaturesList">
      <h3>My Signatures</h3>
      <div id="signatures"></div>
    </div>
  </div>
`;

// Add event listeners
document.getElementById("loginButton")!.addEventListener("click", handleLogin);
document.getElementById("logoutButton")!.addEventListener("click", logout);
document.getElementById("signMessageButton")!.addEventListener("click", () => {
  void (async () => {
    const message = prompt("Enter message to sign:");
    if (message) {
      try {
        await getBasicBlsSigningCanister().sign_message(message);
        alert("Created and stored signature successfully.");
      } catch (error) {
        alert(`Error: ${error as Error}`);
      }
    }
  })();
});

document
  .getElementById("customSignatureButton")!
  .addEventListener("click", () => {
    document
      .getElementById("customSignatureForm")!
      .classList.toggle("hidden", false);
    document.getElementById("signaturesList")!.classList.toggle("hidden", true);
  });

document
  .getElementById("listSignaturesButton")!
  .addEventListener("click", () => {
    void listSignatures();
  });

document
  .getElementById("submitSignatureForm")!
  .addEventListener("submit", (e) => {
    e.preventDefault();
    const message = (document.getElementById("message") as HTMLInputElement)
      .value;
    const signatureHex = (
      document.getElementById("signature") as HTMLInputElement
    ).value;
    const pubkeyHex = (document.getElementById("pubkey") as HTMLInputElement)
      .value;
    const messageBytes = new TextEncoder().encode(message);

    try {
      const signatureBytes = new Uint8Array(
        signatureHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)),
      );
      const pubkeyBytes = new Uint8Array(
        pubkeyHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)),
      );

      const verificationKey = DerivedPublicKey.deserialize(pubkeyBytes);

      const result = verifyBlsSignature(
        verificationKey,
        messageBytes,
        signatureBytes,
      );
      alert(`Verification result: ${result ? "Valid" : "INVALID"}`);
    } catch {
      alert("Verification failed.");
    }
  });

async function listSignatures() {
  const signatures: Array<Signature> =
    await getBasicBlsSigningCanister().get_my_signatures();
  const signaturesDiv = document.getElementById("signatures")!;
  signaturesDiv.innerHTML = "";

  if (signatures.length === 0) {
    signaturesDiv.innerHTML = `
        <div class="no-signatures">
          <p>No signatures have been published yet.</p>
        </div>
      `;
  } else {
    if (!myVerificationKey) {
      const myVerificationKeyRaw =
        await getBasicBlsSigningCanister().get_my_verification_key();
      myVerificationKey = DerivedPublicKey.deserialize(
        Uint8Array.from(myVerificationKeyRaw),
      );
    }
    const myVerificationKeyHex = Array.from(myVerificationKey.publicKeyBytes())
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    for (const signatureData of signatures.slice().reverse()) {
      const signatureHex = Array.from(signatureData.signature)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      // Convert nanoseconds to milliseconds and create a Date object
      const timestamp = new Date(Number(signatureData.timestamp) / 1_000_000);
      const formattedDate = timestamp.toLocaleString();

      const signatureElement = document.createElement("div");
      signatureElement.className = "signature";

      const isValid = verifyBlsSignature(
        myVerificationKey,
        new TextEncoder().encode(signatureData.message),
        Uint8Array.from(signatureData.signature),
      );

      signatureElement.innerHTML = `
        <h5>Signed message: ${signatureData.message}</h5>
        <p class="signature-hex">Signature: ${signatureHex}</p>
        <p class="verification-key-hex">Public key: ${myVerificationKeyHex}</p>
        <p class="verification-status ${isValid ? "valid" : "invalid"}">Verification: ${isValid ? "Valid" : "Invalid"}</p>
        <p class="timestamp">Added: ${formattedDate}</p>
          `;

      signaturesDiv.appendChild(signatureElement);
    }
  }

  document.getElementById("signaturesList")!.classList.toggle("hidden", false);
  document
    .getElementById("customSignatureForm")!
    .classList.toggle("hidden", true);
}

// Initialize auth
void initAuth();
