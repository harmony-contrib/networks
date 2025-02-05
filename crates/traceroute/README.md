# `@ohos-rs/traceroute`

## Install

use`ohpm` to install package.

```shell
ohpm install @ohos-rs/traceroute
```

## API

```ts
export interface HopResult {
  /** hop index */
  hop: number
  /** current hop's target ip address */
  addr?: string
  /** rtt */
  rtt: Array<number>
}

export interface TraceOption {
  /**
    * Max hops
    * @default 64
    */
  maxHops: number
  /**
    * Timeout
    * @default 1
    * @unit second
    */
  timeout: number
  ipVersion?: 'v4' | 'v6' | 'auto'
  /**
    * Retry times every hops
    * @default 3
    */
  reTry?: number
}

export declare function traceRoute(target: string, options?: TraceOption | undefined | null): Promise<HopResult[]>
```

## Usage

```ts
const ret = await traceRoute("www.baidu.com");
```
