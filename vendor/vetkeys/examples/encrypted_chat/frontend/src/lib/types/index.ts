import { Principal } from '@dfinity/principal';

export interface User {
	principal: Principal;
	name: string;
	avatar?: string;
	isOnline: boolean;
	lastSeen?: Date;
}

export interface Message {
	messageId: string;
	chatId: string;
	senderId: string;
	content: string;
	timestamp: Date;
	fileData?: {
		name: string;
		size: number;
		type: string;
		data: Uint8Array;
	};
	vetkeyEpoch: number;
	symmetricRatchetEpoch: number;
}

export interface Chat {
	idStr: string;
	name: string;
	type: 'direct' | 'group';
	// Participants are required by UI components like ChatHeader/ChatListItem
	participants: User[];
	lastMessage?: Message;
	lastActivity: Date;
	isReady: boolean;
	isUpdating: boolean;
	disappearingMessagesDuration: number; // in days, 0 = never
	keyRotationStatus: VetKeyRotationStatus;
	vetKeyEpoch: number;
	symmetricRatchetEpoch: number;
	unreadCount: number;
	avatar?: string;
}

export interface DirectChat extends Chat {
	type: 'direct';
	otherParticipant: User;
}

export interface GroupChat extends Chat {
	type: 'group';
	otherParticipants: User[];
}

export interface VetKeyRotationStatus {
	lastRotation: Date;
	currentEpoch: number;
}

export interface SymmetricRatchetStats {
	currentEpoch: number;
	messagesInCurrentEpoch: number;
	lastRotation: Date;
	nextScheduledRotation: Date;
}

export interface UserConfig {
	cacheRetentionDays: number;
	userId: string;
	userName: string;
	userAvatar?: string;
}

export interface ChatStatus {
	isReady: boolean;
	isUpdating: boolean;
	lastSync: Date;
	additionalInfo?: string;
}

export interface FileUpload {
	file: File;
	preview?: string;
	isValid: boolean;
	error?: string;
}

export type ChatType = 'direct' | 'group';
export type MessageType = 'text' | 'file' | 'image';
export type NotificationType = 'info' | 'warning' | 'error' | 'success';

export interface Notification {
	id: string;
	type: NotificationType;
	title: string;
	message: string;
	isDismissible: boolean;
	duration?: number; // auto-dismiss after ms, undefined = manual dismiss
}

export class StoragePrefixesClass {
	public readonly MESSAGE_PREFIX: string = 'messages';
	public readonly CONFIG_KEY: string = 'user_config';
	public readonly DISCLAIMER_KEY: string = 'disclaimer_dismissed';
	public readonly CHAT_PREFIX: string = 'chat';

	public readonly CHAT_EPOCH_KEY_PREFIX: string = 'chat_epoch_keys';
	public readonly CHAT_IBE_DECRYPTION_KEY_PREFIX: string = 'chat_ibe_decryption_key';
}

export const storagePrefixes = new StoragePrefixesClass();

export class VetKeyEpochError extends Error {
	requiredVetKeyEpoch: bigint;

	constructor(message: string, requiredVetKeyEpoch: bigint) {
		super(message);
		this.name = 'VetKeyEpochError';
		this.requiredVetKeyEpoch = requiredVetKeyEpoch;
		Object.setPrototypeOf(this, VetKeyEpochError.prototype);
	}
}

export class SymmetricRatchetEpochError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'SymmetricRatchetEpochError';
		Object.setPrototypeOf(this, SymmetricRatchetEpochError.prototype);
	}
}
