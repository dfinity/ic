import {
	chatIdToString,
	stringifyBigInt,
	uBigIntTo8ByteUint8ArrayBigEndian,
	u8ByteUint8ArrayBigEndianToUBigInt
} from '$lib/utils';
import {
	EncryptedMaps,
	type AccessRights,
	type ByteBuf,
	type EncryptedMapData,
	type EncryptedMapsClient
} from '@dfinity/vetkeys/encrypted_maps';
import type { ChatId } from '../../declarations/encrypted_chat/encrypted_chat.did';
import type { Principal } from '@dfinity/principal';
import { getActor, getMyPrincipal } from '$lib/stores/auth.svelte';

export class EncryptedCanisterCacheService {
	#encryptedMaps: EncryptedMaps;

	constructor() {
		this.#encryptedMaps = new EncryptedMaps(new EncryptedMapsClientForEncryptedCache());
	}

	async fetchAndDecryptFor(
		chatId: ChatId,
		vetKeyEpoch: bigint
	): Promise<{ keyBytes: Uint8Array; symmetricKeyEpoch: bigint }> {
		console.log(
			`get_my_symmetric_key_cache: chatId=${chatIdToString(chatId)} vetKeyEpoch=${vetKeyEpoch.toString()}`
		);
		const keyCacheBytes = await getActor().get_my_symmetric_key_cache(chatId, vetKeyEpoch);
		if ('Err' in keyCacheBytes) {
			throw new Error('Failed to get key cache bytes: ' + keyCacheBytes.Err);
		} else if (keyCacheBytes.Ok.length === 0) {
			throw new Error('Failed to get key cache bytes: no key cache found');
		}

		const mapName_ = mapName();
		const mapKey = await mapKeyId(chatId, vetKeyEpoch);
		const decryptedBytes = await this.#encryptedMaps.decryptFor(
			getMyPrincipal(),
			mapName_,
			mapKey,
			new Uint8Array(keyCacheBytes.Ok[0])
		);

		console.log(
			`VetKeyEncryptedCache: successfully fetched and decrypted key cache for chatId=${chatIdToString(chatId)} vetKeyEpoch=${vetKeyEpoch.toString()}: ${stringifyBigInt(deserializeCache(decryptedBytes))}`
		);
		return deserializeCache(decryptedBytes);
	}

	async encryptAndStoreFor(
		chatId: ChatId,
		vetKeyEpoch: bigint,
		cache: { keyBytes: Uint8Array; symmetricKeyEpoch: bigint }
	): Promise<void> {
		console.log('encryptAndStoreFor: starting to store the root key in cache: ', cache);
		const mapName_ = mapName();
		const mapKey = await mapKeyId(chatId, vetKeyEpoch);

		const ciphertext = await this.#encryptedMaps.encryptFor(
			getMyPrincipal(),
			mapName_,
			mapKey,
			serializeCache(cache)
		);
		const result = await getActor().update_my_symmetric_key_cache(chatId, vetKeyEpoch, ciphertext);
		if ('Err' in result) {
			throw new Error('Failed to update key cache: ' + result.Err);
		} else {
			console.log(
				`VetKeyEncryptedCache: successfully stored key cache for chatId=${chatIdToString(chatId)} vetKeyEpoch=${vetKeyEpoch.toString()}: ${stringifyBigInt(serializeCache(cache))}`
			);
		}
	}
}

function serializeCache(cache: { keyBytes: Uint8Array; symmetricKeyEpoch: bigint }): Uint8Array {
	return new Uint8Array([
		...cache.keyBytes,
		...uBigIntTo8ByteUint8ArrayBigEndian(cache.symmetricKeyEpoch)
	]);
}

function deserializeCache(data: Uint8Array): { keyBytes: Uint8Array; symmetricKeyEpoch: bigint } {
	return {
		keyBytes: data.slice(0, 32),
		symmetricKeyEpoch: u8ByteUint8ArrayBigEndianToUBigInt(data.slice(32))
	};
}

/* eslint-disable @typescript-eslint/no-unused-vars */
class EncryptedMapsClientForEncryptedCache implements EncryptedMapsClient {
	constructor() {}

	get_accessible_shared_map_names(): Promise<[Principal, ByteBuf][]> {
		throw Error('unavailable EncryptedMaps function get_accessible_shared_map_names');
	}

	get_shared_user_access_for_map(
		owner: Principal,
		mapName: ByteBuf
	): Promise<{ Ok: Array<[Principal, AccessRights]> } | { Err: string }> {
		throw Error('unavailable EncryptedMaps function get_shared_user_access_for_map');
	}

	get_owned_non_empty_map_names(): Promise<Array<ByteBuf>> {
		throw Error('unavailable EncryptedMaps function get_owned_non_empty_map_names');
	}

	get_all_accessible_encrypted_values(): Promise<[[Principal, ByteBuf], [ByteBuf, ByteBuf][]][]> {
		throw Error('unavailable EncryptedMaps function get_all_accessible_encrypted_values');
	}

	get_all_accessible_encrypted_maps(): Promise<Array<EncryptedMapData>> {
		throw Error('unavailable EncryptedMaps function get_all_accessible_encrypted_maps');
	}

	get_encrypted_value(
		mapOwner: Principal,
		mapName: ByteBuf,

		mapKey: ByteBuf
	): Promise<{ Ok: [] | [ByteBuf] } | { Err: string }> {
		throw Error('unavailable EncryptedMaps function get_encrypted_value');
	}

	get_encrypted_values_for_map(
		mapOwner: Principal,
		mapName: ByteBuf
	): Promise<{ Ok: Array<[ByteBuf, ByteBuf]> } | { Err: string }> {
		throw Error('unavailable EncryptedMaps function get_encrypted_values_for_map');
	}

	async get_encrypted_vetkey(
		mapOwner: Principal,
		mapName: ByteBuf,
		transportKey: ByteBuf
	): Promise<{ Ok: ByteBuf } | { Err: string }> {
		const data = new Uint8Array(
			await getActor().get_encrypted_vetkey_for_my_cache_storage(transportKey.inner)
		);
		const result: { Ok: ByteBuf } | { Err: string } = {
			Ok: { inner: data }
		};
		return Promise.resolve(result);
	}

	insert_encrypted_value(
		mapOwner: Principal,
		mapName: ByteBuf,
		mapKey: ByteBuf,
		data: ByteBuf
	): Promise<{ Ok: [] | [ByteBuf] } | { Err: string }> {
		throw Error('unavailable EncryptedMaps function insert_encrypted_value');
	}

	remove_encrypted_value(
		mapOwner: Principal,
		mapName: ByteBuf,
		mapKey: ByteBuf
	): Promise<{ Ok: [] | [ByteBuf] } | { Err: string }> {
		throw Error('unavailable EncryptedMaps function remove_encrypted_value');
	}

	remove_map_values(
		mapOwner: Principal,
		mapName: ByteBuf
	): Promise<{ Ok: Array<ByteBuf> } | { Err: string }> {
		throw Error('unavailable EncryptedMaps function remove_map_values');
	}

	async get_vetkey_verification_key(): Promise<ByteBuf> {
		return { inner: await getActor().get_vetkey_verification_key_for_my_cache_storage() };
	}

	set_user_rights(
		owner: Principal,
		mapName: ByteBuf,
		user: Principal,
		userRights: AccessRights
	): Promise<{ Ok: [] | [AccessRights] } | { Err: string }> {
		throw Error('unavailable EncryptedMaps function set_user_rights');
	}

	get_user_rights(
		owner: Principal,
		mapName: ByteBuf,
		user: Principal
	): Promise<{ Ok: [] | [AccessRights] } | { Err: string }> {
		throw Error('unavailable EncryptedMaps function get_user_rights');
	}

	remove_user(
		owner: Principal,
		mapName: ByteBuf,
		user: Principal
	): Promise<{ Ok: [] | [AccessRights] } | { Err: string }> {
		throw Error('unavailable EncryptedMaps function remove_user');
	}
}
/* eslint-enable @typescript-eslint/no-unused-vars */

function mapName(): Uint8Array {
	return new TextEncoder().encode('encrypted_chat_cache');
}

async function mapKeyId(chat_id: ChatId, vetkey_epoch_id: bigint): Promise<Uint8Array> {
	const input = serializeChatId(chat_id);

	const hashBuffer = await crypto.subtle.digest(
		'SHA-256',
		new Uint8Array([...input, ...uBigIntTo8ByteUint8ArrayBigEndian(vetkey_epoch_id)])
	);
	return new Uint8Array(hashBuffer);
}

function serializeChatId(chatId: ChatId): Uint8Array {
	if ('Direct' in chatId) {
		return new Uint8Array([
			0,
			...chatId.Direct[0].toUint8Array(),
			...chatId.Direct[1].toUint8Array()
		]);
	} else {
		return new Uint8Array([1, ...uBigIntTo8ByteUint8ArrayBigEndian(chatId.Group)]);
	}
}
