import { chatIdToString } from '$lib/utils';
import {
	DerivedPublicKey,
	IbeIdentity,
	IbeSeed,
	IbeCiphertext,
	TransportSecretKey,
	EncryptedVetKey
} from '@dfinity/vetkeys';
import type { ChatId } from '../../declarations/encrypted_chat/encrypted_chat.did';
import { keyStorageService } from './keyStorage';
import type { Principal } from '@dfinity/principal';
import { getActor, getMyPrincipal } from '$lib/stores/auth.svelte';

export class VetKeyResharingService {
	constructor() {}

	async reshareIbeEncryptedVetKeys(
		chatId: ChatId,
		vetkeyEpoch: bigint,
		otherParticipants: Principal[],
		vetKeyBytes: Uint8Array
	): Promise<void> {
		if (otherParticipants.length > 0) {
			console.log(
				'reshareIbeEncryptedVetkeys: ',
				chatId,
				vetkeyEpoch,
				otherParticipants,
				vetKeyBytes
			);
			// try to reshare with other participants
			return await Promise.all(
				otherParticipants.map(async (p) => {
					const ibePublicKey = DerivedPublicKey.deserialize(
						new Uint8Array(await getActor().get_vetkey_resharing_ibe_encryption_key(p))
					);
					const ibeIdentity = IbeIdentity.fromBytes(new Uint8Array());
					const ibeSeed = IbeSeed.random();
					const ibeCiphertext = IbeCiphertext.encrypt(
						ibePublicKey,
						ibeIdentity,
						vetKeyBytes,
						ibeSeed
					);
					const ibeCiphertextBytes = ibeCiphertext.serialize();
					const result: [Principal, Uint8Array<ArrayBufferLike>] = [p, ibeCiphertextBytes];
					return result;
				})
			).then(async (ibeEncryptedVetKeysPromise) => {
				await getActor()
					.reshare_ibe_encrypted_vetkeys(chatId, vetkeyEpoch, ibeEncryptedVetKeysPromise)
					.then((result) => {
						if ('Ok' in result) {
							console.log(
								`Successfully resharded IBE encrypted vetkeys for chat ${chatIdToString(chatId)} vetkeyEpoch ${vetkeyEpoch.toString()}`
							);
						} else {
							console.info(
								`Failed to reshare IBE encrypted vetkeys for chat ${chatIdToString(chatId)} vetkeyEpoch ${vetkeyEpoch.toString()}: `,
								result.Err
							);
						}
					});
			});
		} else {
			console.log('no other participants to reshare vetKey with');
		}
	}

	async fetchResharedIbeEncryptedVetKey(chatId: ChatId, vetkeyEpoch: bigint): Promise<Uint8Array> {
		console.log('fetchResharedIbeEncryptedVetKeys: ', chatId, vetkeyEpoch, getMyPrincipal());
		const tsk = TransportSecretKey.random();
		const myResharedIbeEncryptedVetkey = await getActor().get_my_reshared_ibe_encrypted_vetkey(
			chatId,
			vetkeyEpoch
		);
		if ('Err' in myResharedIbeEncryptedVetkey) {
			throw new Error(
				'Failed to get my reshared IBE encrypted vetkey: ' + myResharedIbeEncryptedVetkey.Err
			);
		} else if (myResharedIbeEncryptedVetkey.Ok.length === 0) {
			throw new Error('Failed to get my reshared IBE encrypted vetkey: no reshared vetkey');
		}
		const ibeCiphertext = IbeCiphertext.deserialize(
			new Uint8Array(myResharedIbeEncryptedVetkey.Ok[0])
		);

		const publicIbeKeyBytes =
			await getActor().get_vetkey_resharing_ibe_encryption_key(getMyPrincipal());
		const publicIbeKey = DerivedPublicKey.deserialize(new Uint8Array(publicIbeKeyBytes));

		const maybeIbeDecryptionKeyFromStorage = await keyStorageService.getIbeDecryptionKey();
		// TODO:cache this key
		const privateEncryptedIbeKeyBytes =
			maybeIbeDecryptionKeyFromStorage ??
			new Uint8Array(
				await getActor().get_vetkey_resharing_ibe_decryption_key(tsk.publicKeyBytes())
			);
		if (!maybeIbeDecryptionKeyFromStorage) {
			console.log(
				`Saving IBE decryption key for chat ${chatIdToString(chatId)} vetkeyEpoch ${vetkeyEpoch.toString()}`
			);
			keyStorageService
				.saveIbeDecryptionKey(new Uint8Array(privateEncryptedIbeKeyBytes))
				.catch((error) => {
					console.error(
						`Failed to save IBE decryption key for chat ${chatIdToString(chatId)} vetkeyEpoch ${vetkeyEpoch.toString()}: `,
						error
					);
				});
		}

		const encryptedVetKey = EncryptedVetKey.deserialize(
			new Uint8Array(privateEncryptedIbeKeyBytes)
		);
		const privateIbeKey = encryptedVetKey.decryptAndVerify(tsk, publicIbeKey, new Uint8Array());

		const ibePlaintext = ibeCiphertext.decrypt(privateIbeKey);
		return ibePlaintext;
	}
}
