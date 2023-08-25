export enum ServiceWorkerEvents {
  SaveICHostInfo = 'SaveICHostInfo',
  ResetServiceWorker = 'ResetServiceWorker',
}

export interface ICHostInfoEvent {
  canisterId: string;
}

export interface SaveICHostInfoMessage {
  action: ServiceWorkerEvents.SaveICHostInfo;
  data: ICHostInfoEvent;
}

export interface ResetServiceWorkerEvent {
  reloadFromWorker: boolean;
}

export interface ResetServiceWorkerMessage {
  action: ServiceWorkerEvents.ResetServiceWorker;
  data: ResetServiceWorkerEvent;
}

export type ServiceWorkerMessages =
  | SaveICHostInfoMessage
  | ResetServiceWorkerMessage;
