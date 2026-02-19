import type { ChatId } from '../../declarations/encrypted_chat/encrypted_chat.did';
import { Principal } from '@dfinity/principal';

export function chatIdToString(chatId: ChatId): string {
	if ('Group' in chatId) return `group/${chatId.Group.toString()}`;
	const [a, b] = chatId.Direct;
	return `direct/${a.toString()}/${b.toString()}`;
}

export function chatIdFromString(str: string): ChatId {
	if (typeof str !== 'string') throw new Error('chatIdStr is not a string but ' + typeof str);
	if (str.startsWith('group/')) return { Group: BigInt(str.slice(6)) };
	const [a, b] = str.split('/').slice(1);
	return { Direct: [Principal.fromText(a), Principal.fromText(b)] };
}

export function chatIdVetKeyEpochToString(chatId: ChatId, vetKeyEpoch: bigint): string {
	return chatIdToString(chatId) + '/' + vetKeyEpoch.toString();
}

export function chatIdVetKeyEpochFromString(str: string): { chatId: ChatId; vetKeyEpoch: bigint } {
	const vetKeyEpochStr = str.split('/').pop()!;
	const chatIdStr = str.slice(0, str.lastIndexOf(`/${vetKeyEpochStr}`));
	return { chatId: chatIdFromString(chatIdStr), vetKeyEpoch: BigInt(vetKeyEpochStr) };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function stringifyBigInt(value: any): string {
	return JSON.stringify(value, (_key, value) => {
		if (typeof value === 'bigint') {
			return value.toString();
		}
		// eslint-disable-next-line @typescript-eslint/no-unsafe-return
		return value;
	});
}

export function uBigIntTo8ByteUint8ArrayBigEndian(value: bigint): Uint8Array {
	if (value < 0n) throw new RangeError('Accpts only bigint n >= 0');

	const bytes = new Uint8Array(8);
	for (let i = 0; i < 8; i++) {
		bytes[i] = Number((value >> BigInt(i * 8)) & 0xffn);
	}
	return bytes;
}

export function u8ByteUint8ArrayBigEndianToUBigInt(bytes: Uint8Array): bigint {
	if (bytes.length !== 8) throw new Error('Expected 8 bytes');
	let value = 0n;
	for (let i = 0; i < 8; i++) {
		value += BigInt(bytes[i]) << BigInt(i * 8);
	}
	return value;
}

export function sizePrefixedBytesFromString(text: string): Uint8Array {
	const bytes = new TextEncoder().encode(text);
	if (bytes.length > 255) {
		throw new Error('Text is too long');
	}
	const size = new Uint8Array(1);
	size[0] = bytes.length & 0xff;
	return new Uint8Array([...size, ...bytes]);
}

export function chatIdsNumMessagesToSummary(
	args: { chatId: ChatId; numMessages: bigint }[]
): string {
	return args.reduce((acc, { chatId, numMessages }) => {
		if ('Direct' in chatId) {
			return (
				acc +
				chatId.Direct[0].toText() +
				' ' +
				chatId.Direct[1].toText() +
				' #' +
				numMessages.toString()
			);
		} else {
			return (
				acc +
				(acc.length > 0 ? ' | ' : '') +
				chatId.Group.toString() +
				' #' +
				numMessages.toString()
			);
		}
	}, '');
}

export function randomNonce(): bigint {
	const buf = new Uint8Array(8);
	globalThis.crypto.getRandomValues(buf);
	let nonce = 0n;
	for (const b of buf) nonce = (nonce << 8n) | BigInt(b);
	return nonce;
}

export function toHex(bytes: Uint8Array): string {
	const hex: string[] = [];
	for (let i = 0; i < bytes.length; i++) {
		const v = bytes[i].toString(16);
		hex[i] = v.length === 1 ? '0' + v : v;
	}
	return hex.join('');
}

export function fromHex(hex: string): Uint8Array {
	if (hex.length % 2 !== 0) throw new Error('Invalid hex string');
	const len = hex.length / 2;
	const bytes = new Uint8Array(len);
	for (let i = 0; i < len; i++) {
		bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
	}
	return bytes;
}
