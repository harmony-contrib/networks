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
  hop: number;
  /** current hop's target ip address */
  addr?: string;
  /** rtt */
  rtt: Array<number>;
}

export interface TraceOption {
  /**
   * Max hops
   * @default 64
   */
  maxHops: number;
  /**
   * Timeout
   * @default 1
   * @unit second
   */
  timeout: number;
  ipVersion?: "v4" | "v6" | "auto";
  /**
   * Retry times every hops
   * @default 3
   */
  reTry?: number;
}

export declare function traceRoute(
  target: string,
  options?: TraceOption | undefined | null
): Promise<HopResult[]>;

export declare function traceRouteWithSignal(
  target: string,
  signal: AbortSignal,
  options?: TraceOption | undefined | null
): Promise<HopResult[]>;
```

## Usage

### Basic usage

```ts
const ret = await traceRoute("www.baidu.com");
```

### Handle onTrace

```ts
const ret = await traceRoute("www.baidu.com", {
  onTrace: (err, data) => {
    console.log(data);
  },
});
```

### Start with cancel

We can cancel the trace with `@ohos-rs/abort-controller`

```ts
import { AbortController } from '@ohos-rs/abort-controller';

const controller = new AbortController();

async traceSignal() {
  try {
    const ret = await traceRouteWithSignal("www.baidu.com", controller.signal, {
      onTrace: (err, data) => {
        console.log(`${JSON.stringify(data)}`)
      }
    });
    console.log(`${JSON.stringify(ret)}`)
  } catch (e) {
    // Cancel will catch the error with `Trace aborted`
    console.log(`${e}`)
  }
}

async cancel() {
  controller.abort()
}
```
