import "./init.ts";
import { HttpAgent, type HttpAgentOptions } from "@dfinity/agent";
import {
    DefaultEncryptedMapsClient,
    EncryptedMaps,
} from "@dfinity/vetkeys/encrypted_maps";

export async function createEncryptedMaps(
    agentOptions: HttpAgentOptions,
): Promise<EncryptedMaps> {
    const agent = await HttpAgent.create({ ...agentOptions });
    // Fetch root key for certificate validation during development
    if (process.env.NODE_ENV !== "production") {
        console.log(`Dev environment - fetching root key...`);

        agent.fetchRootKey().catch((err) => {
            console.warn(
                "Unable to fetch root key. Check to ensure that your local replica is running",
            );
            console.error(err);
        });
    }

    // Creates an actor with using the candid interface and the HttpAgent
    return new EncryptedMaps(
        new DefaultEncryptedMapsClient(
            agent,
            process.env.CANISTER_ID_PASSWORD_MANAGER_WITH_METADATA as string,
        ),
    );
}
