# `@ohos-rs/ping`

## Install

use`ohpm` to install package.

```shell
ohpm install @ohos-rs/ping
```

## API

```ts
export interface PingOptions {
  count: number
  timeout: number
  interval: number
  ipVersion?: 'v4' | 'v6' | 'auto'
}

export interface PingResult {
  host: string
  ip: string
  sequence: number
  ttl: number
  rttMs: number
  success: boolean
  error?: string
  ipVersion: number
}

export declare function pingAsync(host: string, options?: PingOptions | undefined | null): Promise<PingResult[]>
```

## Usage

```ts
const ret = await pingAsync("www.baidu.com");
```
