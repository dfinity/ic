export enum ServiceWorkerEvents {
  SaveICHostInfo = 'SaveICHostInfo',
}

export interface ICHostInfoEvent {
  hostname: string;
  canisterId: string;
  gateway: string;
}

export interface SaveICHostInfoMessage {
  action: ServiceWorkerEvents.SaveICHostInfo;
  data: ICHostInfoEvent;
}
