import { analyzeCode } from "./browser-analysis";
import type { BrowserLanguage } from "./browser-analysis";

self.onmessage=(event: MessageEvent<{source:string;language:BrowserLanguage;filename:string}>)=>{
  try {self.postMessage({result:analyzeCode(event.data.source,event.data.language,event.data.filename)});}
  catch(error){self.postMessage({error:error instanceof Error?error.message:"Code check failed. Try another source file."});}
};
