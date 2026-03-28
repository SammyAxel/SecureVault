declare module 'ua-parser-js' {
  export interface UAParserResult {
    ua: string;
    browser: { name?: string; version?: string; major?: string };
    engine: { name?: string; version?: string };
    os: { name?: string; version?: string };
    device: { type?: string; model?: string; vendor?: string };
    cpu: { architecture?: string };
  }

  export interface IUAParser {
    setUA(uastring: string): IUAParser;
    getBrowser(): { name?: string; version?: string };
    getOS(): { name?: string; version?: string };
    getDevice(): { type?: string; model?: string; vendor?: string };
    getEngine(): { name?: string; version?: string };
    getCPU(): { architecture?: string };
    getResult(): UAParserResult;
  }

  export class UAParser implements IUAParser {
    constructor(uastring?: string);
    setUA(uastring: string): IUAParser;
    getBrowser(): { name?: string; version?: string };
    getOS(): { name?: string; version?: string };
    getDevice(): { type?: string; model?: string; vendor?: string };
    getEngine(): { name?: string; version?: string };
    getCPU(): { architecture?: string };
    getResult(): UAParserResult;
  }

  export default UAParser;
}
