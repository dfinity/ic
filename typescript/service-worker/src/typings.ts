export enum ServiceWorkerEvents {
  SaveICHostInfo = 'SaveICHostInfo',
}

export interface ICHostInfoEvent {
  canisterId: string;
  gateway: string;
}

export interface SaveICHostInfoMessage {
  action: ServiceWorkerEvents.SaveICHostInfo;
  data: ICHostInfoEvent;
}
