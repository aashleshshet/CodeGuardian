import {parser} from "@lezer/python";
import type {FlowStep, StructuralFinding, StructuralResult} from "./analysis-types.ts";

type Node = ReturnType<typeof parser.parse>["topNode"];
type Value = {dynamic: boolean; tainted: boolean; trace: FlowStep[]; ref?: string; constant?: string | boolean; fields?: Map<string, Value>; path?: boolean};
type Env = Map<string, Value>;
type FunctionInfo = {node: Node; closure: Env; defaults: Map<string, Value>};
const clean = (constant?: string | boolean): Value => ({dynamic:false, tainted:false, trace:[], constant});
const unknown = (): Value => ({dynamic:true, tainted:false, trace:[]});
const children = (node: Node): Node[] => {const result:Node[]=[]; for(let child=node.firstChild; child; child=child.nextSibling) result.push(child); return result;};
const punctuation = new Set(["(",")","[","]","{","}",",",":",".","AssignOp","ArithOp","BitOp","CompareOp","LogicOp","UpdateOp","*","**","return","await","yield"]);

/** Parsed, bounded, single-file analysis. It never interprets submitted Python. */
export function analyzePython(source: string): StructuralResult {
  const findings: StructuralFinding[]=[];
  const diagnostics: StructuralResult["diagnostics"]=[];
  let truncated=false, steps=0;
  if(new TextEncoder().encode(source).length>200*1024) return {findings,parsed:false,diagnostics:[{line:1,message:"Source exceeds the 200 KiB analysis limit."}],truncated:true};
  const lineStarts=[0]; for(let i=0;i<source.length;i++) if(source[i]==="\n") lineStarts.push(i+1);
  const line=(offset:number)=>{let low=0,high=lineStarts.length;while(low+1<high){const mid=(low+high)>>1;if(lineStarts[mid]<=offset)low=mid;else high=mid;}return low+1;};
  const text=(node:Node)=>source.slice(node.from,node.to);
  const tick=(depth:number)=>{if(++steps>120000||depth>100){truncated=true;return false;}return true;};
  let tree:ReturnType<typeof parser.parse>;
  try {tree=parser.parse(source);} catch {return {findings,parsed:false,diagnostics:[{line:1,message:"Python parsing failed; structural coverage is incomplete."}],truncated:false};}
  const cursor=tree.cursor(); let nodes=0;
  do {if(++nodes>60000){truncated=true;break;}if(cursor.type.isError&&diagnostics.length<12)diagnostics.push({line:line(cursor.from),message:"Python syntax could not be parsed here; review the surrounding code."});} while(cursor.next());
  // Never describe a recovered syntax tree as complete analysis.
  if(diagnostics.length||truncated)return {findings,parsed:false,diagnostics,truncated};
  const functions=new Map<string,FunctionInfo>();
  const activeFunctions=new Set<number>();
  const calledFunctions=new Set<number>();
  const entryFunctions=new Set<number>();
  const merge=(...values:Value[]):Value=>{
    if(!values.length)return clean();
    if(values.length===1)return {...values[0]};
    const trace:FlowStep[]=[];
    for(const value of values)for(const item of value.trace)if(!trace.some(t=>t.line===item.line&&t.kind===item.kind)&&trace.length<10)trace.push(item);
    return {dynamic:values.some(v=>v.dynamic),tainted:values.some(v=>v.tainted),trace,
      constant:values.every(v=>v.constant!==undefined&&v.constant===values[0].constant)?values[0].constant:undefined,
      ref:values.every(v=>v.ref!==undefined&&v.ref===values[0].ref)?values[0].ref:undefined,
      path:values.every(v=>v.path===true)||undefined};
  };
  const step=(value:Value,node:Node,kind:FlowStep["kind"],label:string):Value=>{
    if(!value.tainted)return value;
    const trace:FlowStep[]=[...value.trace.filter(t=>t.line!==line(node.from)||t.kind!==kind),{line:line(node.from),kind,label}];
    const origin=trace.find(t=>t.kind==="source");
    return {...value,trace:trace.length<=10?trace:[...(origin?[origin]:[]),...trace.slice(-9)]};
  };
  const sourceValue=(node:Node):Value=>({dynamic:true,tainted:true,trace:[{line:line(node.from),kind:"source",label:"External input is read here."}]});
  const add=(node:Node,value:Value,ruleId:string,title:string,cwe:string,message:string,remediation:string,conditions:string[],severity:StructuralFinding["severity"]="high")=>{
    const existing=findings.find(f=>f.ruleId===ruleId&&f.line===line(node.from));
    const trace=value.tainted?step(value,node,"sink","The value reaches this sensitive operation.").trace:undefined;
    if(existing){if(value.tainted&&existing.evidence!=="data_flow"){existing.evidence="data_flow";existing.trace=trace;}return;}
    if(findings.length>=100){truncated=true;return;}
    findings.push({ruleId,title,severity,cwe,line:line(node.from),endLine:line(Math.max(node.from,node.to-1)),message,remediation,conditions,classification:severity==="low"?"secure_coding_suggestion":"potential_vulnerability",evidence:value.tainted?"data_flow":"structural",trace});
  };
  const expressionNodes=(node:Node)=>children(node).filter(n=>!punctuation.has(n.name)&&n.name!=="Comment");
  const decodeString=(node:Node)=>{
    const raw=text(node); const match=/^[rub]*(['"])(?:\1\1)?/i.exec(raw);
    if(!match)return raw;
    const length=raw.slice(match[0].length-3,match[0].length)===match[1].repeat(3)?3:1;
    return raw.slice(match[0].length,-length);
  };
  const canonical=(node:Node|undefined,env:Env):string=>{
    if(!node)return "";
    if(node.name==="VariableName")return env.has(text(node))?(env.get(text(node))?.ref||""):text(node);
    if(node.name==="MemberExpression"){
      const parts=children(node),base=canonical(parts[0],env);
      if(!base)return "";
      if(parts[1]?.name===".")return `${base}.${text(parts[2])}`;
      if(parts[1]?.name==="["&&parts[2]?.name==="String")return `${base}.${decodeString(parts[2])}`;
    }
    return "";
  };
  const isRequest=(name:string)=>/^(?:(?:flask|django\.http)\.)?(?:request|req)\.(?:args|form|json|values|headers|cookies|data|files|GET|POST|body|query_params|query|path_params)(?:\.|$)/.test(name);
  const keywordArgs=(node:Node,env:Env,depth:number):{positional:Value[];keyword:Map<string,Value>}=>{
    const positional:Value[]=[],keyword=new Map<string,Value>();
    const parts=children(node).filter(n=>n.name!=="("&&n.name!==")"&&n.name!=="Comment");
    for(let i=0;i<parts.length;i++){
      const part=parts[i];if(part.name===",")continue;
      if(part.name==="VariableName"&&parts[i+1]?.name==="AssignOp"){
        if(parts[i+2])keyword.set(text(part),evaluate(parts[i+2],env,depth+1));i+=2;
      } else if(part.name==="**") {const value=parts[i+1]?evaluate(parts[++i],env,depth+1):unknown();for(const [key,v]of value.fields||[])keyword.set(key,v);}
      else if(part.name==="*"){if(parts[i+1])positional.push(evaluate(parts[++i],env,depth+1));}
      else positional.push(evaluate(part,env,depth+1));
    }
    return {positional,keyword};
  };
  function evaluate(node:Node|undefined,env:Env,depth=0):Value {
    if(!node||!tick(depth))return unknown();
    const parts=children(node);
    if(node.name==="String")return clean(decodeString(node));
    if(node.name==="Boolean")return clean(text(node)==="True");
    if(["Number","None","Ellipsis","Comment"].includes(node.name))return clean();
    if(node.name==="VariableName")return env.get(text(node))||{...unknown(),ref:text(node)};
    if(node.name==="MemberExpression"){
      const name=canonical(node,env);
      if(isRequest(name)||name==="sys.argv")return sourceValue(node);
      const base=evaluate(parts[0],env,depth+1);
      if(base.fields){const key=parts[1]?.name==="."?text(parts[2]):parts[2]?.name==="String"?decodeString(parts[2]):"";if(base.fields.has(key))return base.fields.get(key)!;}
      if(base.path&&parts[1]?.name==="."){
        const property=text(parts[2]);
        // Keep the path's provenance through parent selection and bound methods.
        // The marker comes only from a resolved pathlib constructor, never a
        // coincidentally named application object or arbitrary .read_text method.
        if(property==="parent")return {...base,ref:undefined};
        return {...base,path:undefined,ref:`pathlib-instance.${property}`};
      }
      return {...merge(base,...parts.filter(n=>!["PropertyName",".","[","]"].includes(n.name)&&n!==parts[0]).map(n=>evaluate(n,env,depth+1))),ref:name||undefined};
    }
    if(node.name==="DictionaryExpression"){
      const fields=new Map<string,Value>(),values:Value[]=[];
      for(let i=0;i<parts.length;i++)if(parts[i].name==="String"&&parts[i+1]?.name===":"&&parts[i+2]){const val=evaluate(parts[i+2],env,depth+1);fields.set(decodeString(parts[i]),val);values.push(val);i+=2;}
      return {...merge(...values),fields};
    }
    if(node.name==="LambdaExpression")return unknown();
    if(node.name==="CallExpression"){
      const callee=parts[0],resolved=canonical(callee,env),calleeParts=children(callee);
      const name=resolved||(callee.name==="MemberExpression"&&calleeParts[1]?.name==="."?`*.${text(calleeParts[2])}`:"");
      const argNode=parts.find(n=>n.name==="ArgList");
      const args=argNode?keywordArgs(argNode,env,depth+1):{positional:[],keyword:new Map<string,Value>()};
      const first=args.positional[0]||args.keyword.get("url")||args.keyword.get("path")||args.keyword.get("file")||args.keyword.get("command")||args.keyword.get("args")||args.keyword.get("query")||args.keyword.get("sql")||args.keyword.get("source")||unknown();
      const combined=merge(...args.positional,...args.keyword.values());
      const receiver=callee.name==="MemberExpression"?evaluate(callee.firstChild||undefined,env,depth+1):clean();
      const pathInput=receiver.path?receiver:name.startsWith("pathlib-instance.")?evaluate(callee,env,depth+1):undefined;
      const pathMethod=callee.name==="MemberExpression"&&calleeParts[1]?.name==="."?text(calleeParts[2]):name.startsWith("pathlib-instance.")?name.slice("pathlib-instance.".length):"";
      if(isRequest(name)||/^(?:flask\.)?(?:request|req)\.(?:get_json|json)$/.test(name)||name==="input"||name==="builtins.input")return sourceValue(node);
      if(/^pathlib\.(?:Path|PosixPath|WindowsPath)$/.test(name))return step({...combined,path:true,ref:undefined},node,"call","A filesystem path is constructed here.");
      if(pathInput&&/^(?:joinpath|resolve|absolute|expanduser|with_name|with_suffix|with_stem)$/.test(pathMethod))return step({...merge(pathInput,combined),path:true,ref:undefined},node,"call","The filesystem path is transformed here; containment is not established.");
      if(pathInput?.tainted&&/^(?:open|read_text|read_bytes|write_text|write_bytes|unlink|rmdir|mkdir|touch|iterdir)$/.test(pathMethod))add(node,pathInput,"python-path-traversal","Input-controlled filesystem path","CWE-22","External input reaches a pathlib filesystem operation through its path receiver.","Resolve the path under an intended root and verify containment after normalization; reject absolute paths and unexpected separators.",["Check symlinks, canonical paths and authorization for the chosen file.","Path.resolve and joining a trusted root do not by themselves enforce containment."]);
      if((name==="eval"||name==="exec"||name==="builtins.eval"||name==="builtins.exec")&&first.dynamic)add(node,first,"dynamic-eval","Dynamic code evaluation","CWE-95","A dynamic value reaches Python code evaluation.","Use a data-only parser and validate its schema; remove code evaluation for untrusted input.",["Verify the source of the value and whether executable code is required."]);
      if(/(?:^|\.)(?:execute|executemany|raw)$/.test(name)&&first.dynamic)add(node,first,"sql-interpolation","Dynamic SQL execution","CWE-89","A dynamic query reaches a database execution API. Bound values do not make a dynamically constructed query safe.","Keep SQL syntax constant and pass values through the driver's bound-parameter API. Allowlist any dynamic identifiers.",["Confirm this is a database API and inspect its placeholder contract.","Review all paths that construct the query, including any sanitization."]);
      if(/^subprocess\.(?:run|call|Popen|check_call|check_output)$/.test(name)&&args.keyword.get("shell")?.constant===true&&first.dynamic)add(node,first,"python-shell","Dynamic command with shell enabled","CWE-78","A dynamic command reaches subprocess with shell=True.","Use a fixed executable and a separate argument list with shell=False. Validate options and operands.",["Determine whether untrusted input can influence the command or its arguments."]);
      if(/^(?:os\.(?:system|popen)|subprocess\.(?:getoutput|getstatusoutput))$/.test(name)&&first.dynamic)add(node,first,"python-os-system","Dynamic shell command","CWE-78","A dynamic value reaches a shell-interpreting API.","Use a library or subprocess with a fixed executable and separate arguments, without a shell.",["Trace the complete command and check argument/option injection."]);
      if(/^(?:pickle|cPickle|dill|shelve)\.(?:load|loads|open)$/.test(name))add(node,first,"python-pickle","Executable deserialization","CWE-502","This deserialization format can execute code from a crafted payload.","Use a data-only format with schema validation. Never load pickle-style data from an untrusted source.",["Verify who can create or modify the serialized data."]);
      if(/^yaml\.(?:load|unsafe_load|full_load)$/.test(name)){
        const loader=args.keyword.get("Loader")||args.positional[1];
        if(!/^(?:yaml\.)?(?:SafeLoader|CSafeLoader)$/.test(loader?.ref||""))add(node,first,"python-unsafe-yaml","YAML object deserialization","CWE-502","The YAML call does not use a recognized SafeLoader; behavior also depends on the installed library version.","Use yaml.safe_load for data-only YAML and validate the resulting structure.",["Check the effective loader and installed PyYAML version.","Verify whether untrusted actors can modify the document."],"medium");
      }
      if(/^(?:requests|httpx)\.(?:get|post|put|patch|delete|head|options|request)$/.test(name)||/^urllib\.request\.urlopen$/.test(name)){
        const target=/\.request$/.test(name)?args.positional[1]||args.keyword.get("url")||unknown():first;
        if(target.tainted)add(node,target,"python-ssrf","Input-controlled outbound request","CWE-918","External input reaches an outbound HTTP request destination.","Allowlist schemes and destinations; reject private, loopback and metadata addresses after DNS resolution and on redirects.",["Confirm whether untrusted users choose the destination.","Validate DNS rebinding, redirects and the actual deployment network boundary."]);
        if(args.keyword.get("verify")?.constant===false)add(node,clean(),"python-tls-verification","Certificate verification disabled","CWE-295","The HTTP request disables certificate verification.","Enable certificate and hostname verification and configure the intended trusted CA bundle.",["Confirm the certificate trust requirements for this connection."],"medium");
      }
      if(/^(?:open|builtins\.open|(?:os|pathlib\.Path)\.(?:open|remove|unlink)|(?:flask\.)?(?:send_file|send_from_directory))$/.test(name)&&first.tainted)add(node,first,"python-path-traversal","Input-controlled filesystem path","CWE-22","External input reaches a filesystem path operation.","Resolve the path under an intended root and verify containment after normalization; reject absolute paths and unexpected separators.",["Check symlinks, canonical paths and authorization for the chosen file.","Some framework helpers perform containment internally; verify the exact API contract."]);
      if(/^(?:flask\.)?render_template_string$/.test(name)&&first.dynamic)add(node,first,"python-template-injection","Dynamic template source","CWE-1336","A dynamic value is used as template source rather than as template data.","Keep template source trusted and fixed. Pass untrusted values only through the template context.",["Confirm whether an attacker controls any portion of the template source."]);
      if(/^(?:flask\.)?redirect$/.test(name)&&first.tainted)add(node,first,"python-open-redirect","Input-controlled redirect","CWE-601","External input reaches a redirect target.","Use known relative destinations or an exact allowlist of trusted origins.",["Inspect canonicalization and alternate URL forms before accepting a destination."],"medium");
      if(/^hashlib\.(?:md5|sha1)$/.test(name))add(node,clean(),"python-weak-hash","Legacy hash algorithm","CWE-327","A legacy hash algorithm is used; its security role is unknown.","Use a modern hash for security-sensitive integrity and a dedicated password hashing function for passwords.",["Distinguish ordinary checksums from password, signature or integrity boundaries."],"low");
      const fn=functions.get(name);
      if(fn){calledFunctions.add(fn.node.from);const returned=runFunction(fn,args.positional,args.keyword,depth+1,true);return step(returned,node,"call","A local function returns this value.");}
      if(/^(?:requests\.Session|httpx\.(?:Client|AsyncClient))$/.test(name))return {...clean(),ref:name.startsWith("requests")?"requests":"httpx"};
      // A sanitizer cannot be considered safe across SQL, shell, URL and path contexts.
      // Transformations preserve taint; parsing, quoting and normalization are not proof of safety.
      return step({...merge(combined,receiver),dynamic:combined.dynamic||receiver.dynamic||!combined.constant},node,"call","A call transforms or passes this value.");
    }
    if(node.name==="BinaryExpression"&&parts.some(part=>part.name==="ArithOp"&&text(part)==="/")){
      const values=expressionNodes(node).map(part=>evaluate(part,env,depth+1));
      const value=merge(...values);
      return values.some(part=>part.path)?step({...value,path:true,ref:undefined},node,"call","A path segment is joined here."):value;
    }
    if(node.name==="FormatString")return merge(...parts.filter(n=>n.name==="FormatReplacement").map(n=>evaluate(n,env,depth+1)));
    return merge(...expressionNodes(node).map(n=>evaluate(n,env,depth+1)));
  }
  const importStatement=(node:Node,env:Env)=>{
    // The import grammar has already been parsed; only identifiers/dots/commas are used.
    const raw=text(node).replace(/[()\n\\]/g," ").replace(/#[^\n]*/g,"");
    const from=/^from\s+([\w.]+)\s+import\s+([\s\S]+)$/.exec(raw);
    const list=from?from[2]:raw.replace(/^import\s+/,"");
    for(const item of list.split(",")){
      const match=/^\s*([\w.]+)(?:\s+as\s+(\w+))?\s*$/.exec(item);if(!match)continue;
      const original=from?`${from[1]}.${match[1]}`:match[1],local=match[2]||(from?match[1]:match[1].split(".")[0]);
      const ref=!from&&!match[2]?match[1].split(".")[0]:original;
      env.set(local,{...clean(),ref});
    }
  };
  const assign=(target:Node,value:Value,env:Env)=>{
    if(target.name==="VariableName")env.set(text(target),step(value,target,"assignment","The value is assigned here."));
    else if(target.name==="MemberExpression"){
      const parts=children(target);if(parts[0]?.name==="VariableName"){
        const key=parts[1]?.name==="."?text(parts[2]):parts[2]?.name==="String"?decodeString(parts[2]):"";
        if(key){const old=env.get(text(parts[0]))||clean(),fields=new Map(old.fields);fields.set(key,value);env.set(text(parts[0]),{...merge(old,value),fields});}
      }
    }else for(const item of expressionNodes(target))assign(item,value,env);
  };
  const mergeEnvs=(target:Env,branches:Env[])=>{for(const key of new Set(branches.flatMap(e=>[...e.keys()])))target.set(key,merge(...branches.map(e=>e.get(key)||unknown())));};
  const parameters=(node:Node):{name:Node;defaultValue?:Node}[]=>{
    const list=children(node).find(n=>n.name==="ParamList");if(!list)return [];
    const groups:Node[][]=[[]];for(const item of children(list)){if(item.name===",")groups.push([]);else if(item.name!=="("&&item.name!==")")groups.at(-1)!.push(item);}
    return groups.flatMap(group=>{const name=group.find(n=>n.name==="VariableName");if(!name)return [];const at=group.findIndex(n=>n.name==="AssignOp");return [{name,defaultValue:at>=0?group[at+1]:undefined}];});
  };
  const registerFunction=(node:Node,env:Env,evaluateDefaults:boolean)=>{
    const nameNode=children(node).find(n=>n.name==="VariableName");if(!nameNode)return;
    const name=text(nameNode),ref=`local-function:${node.from}`,defaults=new Map<string,Value>();
    // Python evaluates defaults when the definition executes, not on each call.
    if(evaluateDefaults)for(const param of parameters(node))if(param.defaultValue)defaults.set(text(param.name),evaluate(param.defaultValue,env));
    functions.set(ref,{node,closure:env,defaults});env.set(name,{...clean(),ref});
  };
  function statement(node:Node,env:Env,returns:Value[],depth=0):void {
    if(!tick(depth))return;
    const parts=children(node);
    if(node.name==="Comment")return;
    if(node.name==="ImportStatement"){importStatement(node,env);return;}
    if(node.name==="FunctionDefinition"){
      registerFunction(node,env,true);return;
    }
    if(node.name==="ClassDefinition"){
      const nameNode=parts.find(n=>n.name==="VariableName");if(nameNode)env.set(text(nameNode),unknown());
      const body=parts.find(n=>n.name==="Body");if(body)statement(body,new Map(env),[],depth+1);return;
    }
    if(node.name==="ReturnStatement"){returns.push(merge(...expressionNodes(node).map(n=>evaluate(n,env,depth+1))));return;}
    if(node.name==="AssignStatement"||node.name==="UpdateStatement"){
      const assignments=parts.flatMap((n,i)=>n.name==="AssignOp"||n.name==="UpdateOp"?[i]:[]);
      if(!assignments.length)return;
      const values=parts.slice(assignments.at(-1)!+1).filter(n=>n.name!==",").map(n=>evaluate(n,env,depth+1));
      let start=0;
      for(const at of assignments){
        const targets=parts.slice(start,at).filter(n=>n.name!==","&&n.name!=="TypeDef");
        if(targets.length===values.length&&values.length>1)targets.forEach((target,i)=>assign(target,values[i],env));
        else {let value=merge(...values);if(node.name==="UpdateStatement")value=merge(value,...targets.map(n=>evaluate(n,env,depth+1)));targets.forEach(n=>assign(n,value,env));}
        start=at+1;
      }return;
    }
    if(["IfStatement","TryStatement","MatchStatement"].includes(node.name)){
      const exhaustive=node.name==="IfStatement"&&parts.some(n=>n.name==="else");
      const branches:Env[]=exhaustive?[]:[new Map(env)];
      for(const part of parts){if(part.name==="Body"){const branch=new Map(env);statement(part,branch,returns,depth+1);branches.push(branch);}else if(!["if","elif","else","try","except","finally","match"].includes(part.name))evaluate(part,env,depth+1);}
      mergeEnvs(env,branches);return;
    }
    if(node.name==="ForStatement"||node.name==="WhileStatement"){
      const branch=new Map(env),inAt=parts.findIndex(n=>n.name==="in");
      if(inAt>=0){const value=evaluate(parts[inAt+1],env,depth+1);for(const target of parts.slice(1,inAt).filter(n=>n.name!==","))assign(target,value,branch);}
      for(const part of parts)if(part.name==="Body")statement(part,branch,returns,depth+1);
      mergeEnvs(env,[env,branch]);return;
    }
    if(["Script","Body","DecoratedStatement"].includes(node.name)){for(const part of parts)if(!punctuation.has(part.name)&&part.name!=="Decorator"){if(node.name==="DecoratedStatement"&&part.name==="FunctionDefinition")entryFunctions.add(part.from);statement(part,env,returns,depth+1);}return;}
    if(node.name.endsWith("Statement")&&node.name!=="ExpressionStatement"){
      for(const part of parts)if(part.name==="Body")statement(part,new Map(env),returns,depth+1);else evaluate(part,env,depth+1);return;
    }
    evaluate(node,env,depth+1);
  }
  function runFunction(fn:FunctionInfo,args:Value[],keywords:Map<string,Value>,depth:number,actualCall=false):Value {
    if(depth>40||activeFunctions.size>=4||activeFunctions.has(fn.node.from)){truncated=true;return merge(...args,...keywords.values(),unknown());}
    const parts=children(fn.node),body=parts.find(n=>n.name==="Body"),local=new Map(fn.closure);
    const names=parameters(fn.node).map(p=>p.name);
    names.forEach((n,i)=>{
      const supplied=keywords.get(text(n))||args[i]||(actualCall?fn.defaults.get(text(n)):undefined);
      // Framework request objects expose untrusted fields, not an untrusted object as a whole.
      // Name/annotation recognition is heuristic and still reported as potential risk.
      const requestParameter=/^(?:request|req)$/.test(text(n))||n.nextSibling?.name==="TypeDef"&&/\bRequest\b/.test(text(n.nextSibling));
      const entry=merge(unknown(),...(fn.defaults.has(text(n))?[fn.defaults.get(text(n))!]:[]));
      local.set(text(n),supplied||{...entry,ref:requestParameter?"request":undefined});
    });
    // Python locals are bound throughout a function, even before their first assignment.
    const collect=(node:Node,level=0)=>{if(level>60){truncated=true;return;}if(node.name==="FunctionDefinition"||node.name==="ClassDefinition")return;if(node.name==="AssignStatement"){const c=children(node),at=c.findIndex(n=>n.name==="AssignOp");for(const n of c.slice(0,at))if(n.name==="VariableName"&&!names.some(p=>text(p)===text(n)))local.set(text(n),unknown());}for(const c of children(node))collect(c,level+1);};
    if(body)collect(body);
    activeFunctions.add(fn.node.from);const returns:Value[]=[];
    if(body)statement(body,local,returns,depth+1);
    activeFunctions.delete(fn.node.from);return returns.length?merge(...returns):clean();
  }
  const env:Env=new Map();
  // First register top-level definitions for forward calls. Imports are processed in order below.
  for(const node of children(tree.topNode))if(node.name==="FunctionDefinition")registerFunction(node,env,false);
  statement(tree.topNode,env,[]);
  // Inspect uncalled entrypoints too, with unknown (not automatically untrusted) parameters.
  for(const fn of [...functions.values()]){if(steps>120000){truncated=true;break;}if(!calledFunctions.has(fn.node.from)||entryFunctions.has(fn.node.from))runFunction(fn,[],new Map(),0);}
  return {findings,parsed:true,diagnostics,truncated};
}
