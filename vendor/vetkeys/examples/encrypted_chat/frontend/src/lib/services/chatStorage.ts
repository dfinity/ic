import { get, set, del, clear, keys } from 'idb-keyval';
import type { Message, Chat, UserConfig } from '../types';
import { storagePrefixes } from '../types';
import * as cbor from 'cbor-x';
import { fromHex, toHex } from '$lib/utils';
import { Principal } from '@dfinity/principal';

// IndexedDB storage service for persistent chat data
export class ChatStorageService {
	async saveMessage(message: Message): Promise<void> {
		console.log(
			`ChatStorageService: Saving from chat ${message.chatId} message ${message.messageId} to indexedDB`
		);

		const encodedMessage = toHex(cbor.encode(message) as Uint8Array);

		await set([storagePrefixes.MESSAGE_PREFIX, message.chatId, message.messageId], encodedMessage);
	}

	async getMessages(chatId: string): Promise<Message[]> {
		const allKeys = await keys();
		const chatMessageKeys = allKeys.filter(
			(key) => Array.isArray(key) && key[0] === storagePrefixes.MESSAGE_PREFIX && key[1] === chatId
		);
		if (chatMessageKeys.length === 0) {
			console.log(`ChatStorageService: No messages found in indexedDB for chat ${chatId}`);
		} else {
			console.log(
				`ChatStorageService: Loaded ${chatMessageKeys.length} messages in indexedDB for chat ${chatId}`
			);
		}

		const messages: Message[] = [];
		for (const key of chatMessageKeys) {
			const encodedMessage = (await get(key)) as string;
			if (!encodedMessage) {
				console.error('ChatStorageService: Failed to get encoded message from indexedDB');
				continue;
			}
			const message = cbor.decode(fromHex(encodedMessage)) as Message;
			if (message) {
				// Ensure timestamp is a Date object
				if (typeof message.timestamp === 'string') {
					message.timestamp = new Date(message.timestamp);
				}
				messages.push(message);
			}
		}

		// Sort by timestamp
		return messages.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
	}

	async deleteMessage(chatId: string, messageId: string): Promise<void> {
		await del([storagePrefixes.MESSAGE_PREFIX, chatId, messageId]);
	}

	async containsMessage(chatId: string, messageId: string): Promise<boolean> {
		return (await keys()).some(
			(key) =>
				Array.isArray(key) &&
				key[0] === storagePrefixes.MESSAGE_PREFIX &&
				key[1] === chatId &&
				key[2] === messageId
		);
	}

	// Chat metadata storage
	async saveChat(chat: Chat): Promise<void> {
		console.log(`ChatStorageService: Saving chat ${chat.idStr} to indexedDB`);
		// example of the JSON encoding is
		const value = JSON.stringify(chat, (key, value) => {
			if (value instanceof Principal) {
				const principal = {
					__principal__: true,
					value: value.toText()
				};
				return principal;
			}
			return value as unknown;
		});
		if (!value) {
			throw new Error('ChatStorageService: Failed to stringify chat');
		}
		await set([storagePrefixes.CHAT_PREFIX, chat.idStr], value);
	}

	async deleteChat(chatId: string): Promise<void> {
		await del([storagePrefixes.CHAT_PREFIX, chatId]);
	}

	async getAllChats(): Promise<Chat[]> {
		const allKeys = await keys();
		const chatKeys = allKeys.filter((key) => {
			console.log(
				'getAllChats: key',
				key,
				Array.isArray(key) && key[0] === storagePrefixes.CHAT_PREFIX
			);
			return Array.isArray(key) && key[0] === storagePrefixes.CHAT_PREFIX;
		});

		console.log(`ChatStorageService: Getting ${chatKeys.length} chats from indexedDB`);

		const chats: Chat[] = [];
		for (const key of chatKeys) {
			const chatStr = (await get(key)) as string;
			if (chatStr) {
				console.log('getAllChats: getting key', key, ' with value ', chatStr);
				chats.push(
					JSON.parse(chatStr, (key, value) => {
						if (typeof value === 'object' && value !== null && '__principal__' in value) {
							// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
							const principal = Principal.fromText(value.__principal__ as string);
							return principal;
						}
						return value as unknown;
					}) as Chat
				);
			}
		}
		return chats;
	}

	// User configuration
	async saveUserConfig(config: UserConfig): Promise<void> {
		console.log(`ChatStorageService: Saving user config to indexedDB`);
		await set([storagePrefixes.CONFIG_KEY], config);
	}

	async getUserConfig(): Promise<UserConfig | null> {
		console.log(`ChatStorageService: Getting user config from indexedDB`);
		return (await get([storagePrefixes.CONFIG_KEY])) || null;
	}

	getMyUserConfig(): UserConfig {
		console.log(`ChatStorageService: Getting my user config from indexedDB`);
		return {
			cacheRetentionDays: 7,
			userId: 'Me',
			userName: 'You',
			userAvatar: '👤'
		};
	}

	// Disclaimer
	async setDisclaimerDismissed(): Promise<void> {
		console.log(`ChatStorageService: Setting disclaimer dismissed to true in indexedDB`);
		await set([storagePrefixes.DISCLAIMER_KEY], true);
	}

	async isDisclaimerDismissed(): Promise<boolean> {
		console.log(`ChatStorageService: Getting disclaimer dismissed from indexedDB`);
		return (await get([storagePrefixes.DISCLAIMER_KEY])) || false;
	}

	// Cache cleanup based on user config
	async cleanupUserCache(retentionDays: number): Promise<void> {
		console.log(`ChatStorageService: Cleaning up user cache for ${retentionDays} days`);
		const cutoffDate = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
		const allKeys = await keys();

		// Clean up old message keys
		for (const key of allKeys) {
			if (typeof key === 'string' && key.startsWith(storagePrefixes.MESSAGE_PREFIX)) {
				const message = (await get(key)) as Message;
				if (message && new Date(message.timestamp) < cutoffDate) {
					await del(key);
				}
			}
		}
	}

	async discardCacheCompletely(): Promise<void> {
		console.log(`ChatStorageService: Discarding cache completely`);
		await clear();
	}

	// Clear all data (for testing/reset)
	async clearAllData(): Promise<void> {
		console.log(`ChatStorageService: Clearing all data from indexedDB`);
		await clear();
	}
}

export const chatStorageService = new ChatStorageService();
