# `@ohos-rs/traceroute`

## !Note: We use `ICMP(DGRAM)` to implement the traceroute, but HarmonyOS will block ICMP packets if ttl is too small.

## Install

use`ohpm` to install package.

```shell
ohpm install @ohos-rs/traceroute
```

## API

```ts
export interface HopResult {
  hop: number
  addr?: string
  rtt: Array<number>
}

export interface TraceOption {
  maxHops: number
  timeout: number
  ipVersion?: 'v4' | 'v6' | 'auto'
}

export declare function traceRoute(target: string, options?: TraceOption | undefined | null): Promise<HopResult[]>
```

## Usage

```ts
const ret = await traceRoute("www.baidu.com");
```
