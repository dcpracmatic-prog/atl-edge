// MORPH-8 Structural Gate v0.3 - standalone C++17
// Deterministic proposal validator/repairer for LLM/agent output.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
typedef struct {
    int decision;          /* 0=REJECT, 1=ACCEPT, 2=REPAIR */
    double health;         /* structural score [0,1], not probability */
    double energy;         /* 1-health */
    uint32_t violations;   /* hard structural/policy-context violations */
    uint32_t state_mask;   /* 8 deterministic structural projections */
    uint32_t structural_mask; /* 1=dimension satisfied */
    uint32_t repairs;      /* semantically neutral formatting repairs */
} MorphDecision;

int morph_predigest(const char* input, std::size_t input_len,
                    const char* policy, std::size_t policy_len,
                    char* repaired, std::size_t repaired_cap,
                    MorphDecision* out);
const char* morph_version(void);
}

namespace {

enum Violation : uint32_t {
    V_EMPTY   = 1u << 0,
    V_SIZE    = 1u << 1,
    V_SYNTAX  = 1u << 2,
    V_SCHEMA  = 1u << 3,
    V_TOOL    = 1u << 4,
    V_ACTION  = 1u << 5,
    V_CAUSAL  = 1u << 6,
    V_CONTROL = 1u << 7
};

enum Repair : uint32_t { R_TRIM=1u<<0, R_FENCE=1u<<1, R_CRLF=1u<<2 };

static constexpr std::size_t MAX_INPUT_BYTES = 65536;
static constexpr std::size_t MAX_POLICY_BYTES = 16384;
static constexpr std::size_t MAX_DEPTH = 32;
static constexpr std::size_t MAX_ARRAY_ITEMS = 1024;
static constexpr std::size_t MAX_OBJECT_FIELDS = 128;
static constexpr std::size_t MAX_STRING_BYTES = 16384;
static constexpr std::size_t MAX_STEPS = 128;
static constexpr std::size_t MAX_DEPS = 32;

struct Policy {
    std::set<std::string> allow_tools;
    std::set<std::string> deny_actions;
    std::set<std::string> allow_actions;
    std::set<std::string> allow_operations;
    std::set<std::string> deny_operations;
    std::set<std::string> required;
    std::set<std::string> deny_fields;
    bool tool_policy_declared = false;
};

struct Json {
    enum Type { NUL, BOOL, NUMBER, STRING, ARRAY, OBJECT } type = NUL;
    bool b = false;
    std::string scalar;
    std::vector<Json> a;
    std::map<std::string, Json> o;
};

class Parser {
    const std::string& s; size_t p=0; size_t depth=0;
    static bool hex(char c, unsigned& v){
        if(c>='0'&&c<='9'){v=c-'0';return true;}
        if(c>='a'&&c<='f'){v=c-'a'+10;return true;}
        if(c>='A'&&c<='F'){v=c-'A'+10;return true;}
        return false;
    }
    void ws(){while(p<s.size() && (s[p]==' '||s[p]=='\t'||s[p]=='\n'||s[p]=='\r'))++p;}
    bool eat(char c){ws();if(p<s.size()&&s[p]==c){++p;return true;}return false;}
    bool string(std::string& out){
        if(p>=s.size()||s[p++]!='"')return false; out.clear();
        while(p<s.size()){
            unsigned char c=(unsigned char)s[p++];
            if(c=='"')return out.size()<=MAX_STRING_BYTES;
            if(c<0x20)return false;
            if(c=='\\'){
                if(p>=s.size())return false; char e=s[p++];
                switch(e){
                    case '"':case '\\':case '/':out.push_back(e);break;
                    case 'b':out.push_back('\b');break; case 'f':out.push_back('\f');break;
                    case 'n':out.push_back('\n');break; case 'r':out.push_back('\r');break; case 't':out.push_back('\t');break;
                    case 'u': {
                        if(p+4>s.size())return false; unsigned cp=0,v=0;
                        for(int k=0;k<4;++k){if(!hex(s[p++],v))return false;cp=(cp<<4)|v;}
                        if(cp>=0xD800&&cp<=0xDFFF)return false; // reject lone surrogate; no semantic repair
                        if(cp<=0x7F)out.push_back((char)cp);
                        else if(cp<=0x7FF){out.push_back((char)(0xC0|(cp>>6)));out.push_back((char)(0x80|(cp&63)));}
                        else {out.push_back((char)(0xE0|(cp>>12)));out.push_back((char)(0x80|((cp>>6)&63)));out.push_back((char)(0x80|(cp&63)));}
                        break;
                    }
                    default:return false;
                }
            } else out.push_back((char)c);
            if(out.size()>MAX_STRING_BYTES)return false;
        }
        return false;
    }
    bool number(std::string& out){
        ws();size_t b=p;
        if(p<s.size()&&s[p]=='-')++p; if(p>=s.size())return false;
        if(s[p]=='0')++p; else {if(!std::isdigit((unsigned char)s[p]))return false;while(p<s.size()&&std::isdigit((unsigned char)s[p]))++p;}
        if(p<s.size()&&s[p]=='.'){++p;if(p>=s.size()||!std::isdigit((unsigned char)s[p]))return false;while(p<s.size()&&std::isdigit((unsigned char)s[p]))++p;}
        if(p<s.size()&&(s[p]=='e'||s[p]=='E')){++p;if(p<s.size()&&(s[p]=='+'||s[p]=='-'))++p;if(p>=s.size()||!std::isdigit((unsigned char)s[p]))return false;while(p<s.size()&&std::isdigit((unsigned char)s[p]))++p;}
        out=s.substr(b,p-b);return true;
    }
    bool value(Json& v){
        ws();if(p>=s.size()||depth>MAX_DEPTH)return false;
        if(s[p]=='{')return object(v); if(s[p]=='[')return array(v); if(s[p]=='"'){v.type=Json::STRING;return string(v.scalar);}
        if(s.compare(p,4,"true")==0){p+=4;v.type=Json::BOOL;v.b=true;return true;}
        if(s.compare(p,5,"false")==0){p+=5;v.type=Json::BOOL;v.b=false;return true;}
        if(s.compare(p,4,"null")==0){p+=4;v.type=Json::NUL;return true;}
        return number(v.scalar);
    }
    bool array(Json& v){
        if(++depth>MAX_DEPTH)return false; v.type=Json::ARRAY;v.a.clear();if(!eat('[')){--depth;return false;}ws();if(eat(']')){--depth;return true;}
        while(true){if(v.a.size()>=MAX_ARRAY_ITEMS){--depth;return false;}Json x;if(!value(x)){--depth;return false;}v.a.push_back(std::move(x));ws();if(eat(']')){--depth;return true;}if(!eat(',')){--depth;return false;}}
    }
    bool object(Json& v){
        if(++depth>MAX_DEPTH)return false; v.type=Json::OBJECT;v.o.clear();if(!eat('{')){--depth;return false;}ws();if(eat('}')){--depth;return true;}
        while(true){if(v.o.size()>=MAX_OBJECT_FIELDS){--depth;return false;}std::string k;ws();if(!string(k)){--depth;return false;}if(!eat(':')){--depth;return false;}Json x;if(!value(x)){--depth;return false;}if(v.o.count(k)){--depth;return false;}v.o.emplace(std::move(k),std::move(x));ws();if(eat('}')){--depth;return true;}if(!eat(',')){--depth;return false;}}
    }
public: explicit Parser(const std::string& x):s(x){} bool parse(Json& v){if(!value(v))return false;ws();return p==s.size();}
};

static std::string trim(const std::string& s){size_t a=0,b=s.size();while(a<b&&std::isspace((unsigned char)s[a]))++a;while(b>a&&std::isspace((unsigned char)s[b-1]))--b;return s.substr(a,b-a);}
static bool has(const Json& o,const std::string& k){return o.type==Json::OBJECT&&o.o.find(k)!=o.o.end();}
static const Json* get(const Json& o,const std::string& k){if(o.type!=Json::OBJECT)return nullptr;auto it=o.o.find(k);return it==o.o.end()?nullptr:&it->second;}
static bool strval(const Json* j,std::string& out){if(!j||j->type!=Json::STRING)return false;out=j->scalar;return true;}

static Policy parse_policy(const std::string& p){
    Policy x;std::istringstream in(p);std::string line;std::size_t n=0;
    while(std::getline(in,line)){if(++n>1024)break;line=trim(line);if(line.empty()||line[0]=='#')continue;auto eq=line.find('=');if(eq==std::string::npos)continue;std::string k=trim(line.substr(0,eq)),v=trim(line.substr(eq+1));
        if(k=="allow_tool"&&!v.empty()){x.allow_tools.insert(v);x.tool_policy_declared=true;}
        else if(k=="deny_action"&&!v.empty())x.deny_actions.insert(v);
        else if(k=="allow_action"&&!v.empty())x.allow_actions.insert(v);
        else if(k=="allow_operation"&&!v.empty())x.allow_operations.insert(v);
        else if(k=="deny_operation"&&!v.empty())x.deny_operations.insert(v);
        else if(k=="require"&&!v.empty())x.required.insert(v);
        else if(k=="deny_field"&&!v.empty())x.deny_fields.insert(v);
    } return x;
}

static std::string repair_text(const std::string& raw,uint32_t& repairs){
    std::string s=raw;
    if(s.find('\r')!=std::string::npos){std::string t;t.reserve(s.size());for(char c:s)if(c!='\r')t.push_back(c);s.swap(t);repairs|=R_CRLF;}
    std::string t=trim(s);if(t!=s){s=t;repairs|=R_TRIM;}
    if(s.size()>=6&&s.rfind("```",0)==0&&s.rfind("```")==s.size()-3){size_t nl=s.find('\n');if(nl!=std::string::npos){std::string body=trim(s.substr(nl+1,s.size()-nl-4));if(body!=s){s=body;repairs|=R_FENCE;}}}
    return s;
}

static bool required_ok(const Json& root,const Policy& p){for(const auto&k:p.required)if(!has(root,k))return false;return true;}
static bool tool_ok(const Json& root,const Policy& p){
    const Json* t=get(root,"tool");std::string v;
    if(!p.tool_policy_declared) return false; // fail closed: no allowlist => no tool execution
    return strval(t,v)&&p.allow_tools.count(v)>0;
}
static bool operation_ok(const Json& root,const Policy& p){
    const Json* a=get(root,"operation");std::string v;
    if(!strval(a,v)) return false;
    if(p.deny_operations.count(v)>0) return false;
    if(!p.allow_operations.empty() && p.allow_operations.count(v)==0) return false;
    return true;
}
static bool action_ok(const Json& root,const Policy& p){
    const Json* a=get(root,"action");
    if(!a) return true;
    std::string v;
    if(!strval(a,v)) return false;
    if(p.deny_actions.count(v)>0) return false;
    if(!p.allow_actions.empty() && p.allow_actions.count(v)==0) return false;
    return true;
}
static bool steps_policy_ok(const Json& root,const Policy& p){
    const Json* steps=get(root,"steps");
    if(!steps) return true;
    if(steps->type!=Json::ARRAY) return false;
    for(const Json& st:steps->a){
        if(st.type!=Json::OBJECT) return false;
        std::string tool, action, operation;
        if(!strval(get(st,"tool"),tool) || !p.tool_policy_declared || p.allow_tools.count(tool)==0) return false;
        if(!strval(get(st,"operation"),operation)) return false;
        if(p.deny_operations.count(operation)>0) return false;
        if(!p.allow_operations.empty() && p.allow_operations.count(operation)==0) return false;
        const Json* a=get(st,"action");
        if(a){
            if(!strval(a,action)) return false;
            if(p.deny_actions.count(action)>0) return false;
            if(!p.allow_actions.empty() && p.allow_actions.count(action)==0) return false;
        }
        for(const auto& k:p.deny_fields) if(has(st,k)) return false;
    }
    return true;
}
static bool control_ok(const Json& root,const Policy& p){
    static const char* executable_fields[]={"shell","exec","command"};
    for(const char* k:executable_fields) if(has(root,k) && p.deny_fields.count(k)==0) return false;
    for(const auto&k:p.deny_fields) if(has(root,k)) return false;
    return true;
}

static bool causal_ok(const Json& root){
    const Json* steps=get(root,"steps");if(!steps)return true;if(steps->type!=Json::ARRAY||steps->a.size()>MAX_STEPS)return false;
    std::map<std::string,std::set<std::string>> deps;
    for(const Json& st:steps->a){
        if(st.type!=Json::OBJECT)return false;std::string id,tool,op;
        if(!strval(get(st,"id"),id)||id.empty()||deps.count(id))return false;
        if(!strval(get(st,"tool"),tool)||tool.empty())return false;
        if(!strval(get(st,"operation"),op)||op.empty())return false;
        const Json* d=get(st,"depends_on");deps[id]={};
        if(d){if(d->type!=Json::ARRAY||d->a.size()>MAX_DEPS)return false;for(const Json&x:d->a){std::string q;if(!strval(&x,q)||q.empty())return false;deps[id].insert(q);}}
    }
    for(const auto&[id,ds]:deps)for(const auto&d:ds)if(!deps.count(d))return false;
    enum C{W,G,B};std::map<std::string,C> color;
    std::function<bool(const std::string&)> dfs=[&](const std::string&u){color[u]=G;for(const auto&v:deps[u]){if(color[v]==G)return false;if(color[v]==W&&!dfs(v))return false;}color[u]=B;return true;};
    for(const auto&kv:deps)if(color[kv.first]==W&&!dfs(kv.first))return false;return true;
}

static uint32_t structural_mask(uint32_t v){uint32_t m=0;if(!(v&V_SYNTAX))m|=1u<<0;if(!(v&V_SCHEMA))m|=1u<<1;if(!(v&V_TOOL))m|=1u<<2;if(!(v&V_ACTION))m|=1u<<3;if(!(v&V_CAUSAL))m|=1u<<4;if(!(v&V_CONTROL))m|=1u<<5;if(!(v&V_SIZE))m|=1u<<6;if(!(v&V_EMPTY))m|=1u<<7;return m;}
static uint32_t state_mask(uint32_t v){
    uint32_t mask=0;bool syntax=!(v&V_SYNTAX),schema=!(v&V_SCHEMA),tool=!(v&V_TOOL),action=!(v&V_ACTION),causal=!(v&V_CAUSAL),control=!(v&V_CONTROL),size=!(v&V_SIZE),nonempty=!(v&V_EMPTY);
    for(int i=0;i<8;++i){int sx=(i&1)?1:-1,sy=(i&2)?1:-1,sz=(i&4)?1:-1;bool ok=nonempty&&size&&syntax&&schema;if(sx<0)ok=ok&&tool;if(sy<0)ok=ok&&action;if(sz<0)ok=ok&&causal;if((sx+sy+sz)>0)ok=ok&&control;if(ok)mask|=(1u<<i);}return mask;
}
static double structural_score(uint32_t v){int n=0;for(uint32_t x=v;x;x&=x-1)++n;return std::max(0.0,1.0-0.125*n);}

} // namespace

extern "C" const char* morph_version(void){return "MORPH-8 Structural Gate 0.4";}

extern "C" int morph_predigest(const char* input,std::size_t input_len,const char* policy,std::size_t policy_len,char* repaired,std::size_t repaired_cap,MorphDecision* out){
    if(!out)return -2;*out=MorphDecision{0,0.0,0.0,0,0,0,0};
    if(!input){out->violations=V_EMPTY;out->structural_mask=structural_mask(V_EMPTY);return -1;}
    if(input_len>MAX_INPUT_BYTES){out->violations=V_SIZE;out->structural_mask=structural_mask(V_SIZE);out->health=structural_score(V_SIZE);out->energy=1.0-out->health;out->state_mask=state_mask(V_SIZE);return 0;}
    if(policy_len>MAX_POLICY_BYTES){out->violations=V_CONTROL;out->structural_mask=structural_mask(V_CONTROL);out->health=structural_score(V_CONTROL);out->energy=1.0-out->health;out->state_mask=state_mask(V_CONTROL);return 0;}
    std::string raw(input,input_len),s;uint32_t repairs=0;s=repair_text(raw,repairs);Policy pol=parse_policy(policy?std::string(policy,policy_len):std::string());uint32_t v=0;
    if(s.empty())v|=V_EMPTY;if(s.size()>MAX_INPUT_BYTES)v|=V_SIZE;
    Json root;bool parsed=false;if(!s.empty()){Parser p(s);parsed=p.parse(root);}if(!parsed)v|=V_SYNTAX;
    if(parsed&&root.type!=Json::OBJECT)v|=V_SCHEMA;
    if(parsed&&root.type==Json::OBJECT){
        if(!required_ok(root,pol))v|=V_SCHEMA;
        if(!tool_ok(root,pol))v|=V_TOOL;
        if(!operation_ok(root,pol) || !action_ok(root,pol) || !steps_policy_ok(root,pol))v|=V_ACTION;
        if(!causal_ok(root))v|=V_CAUSAL;
        if(!control_ok(root,pol))v|=V_CONTROL;
    }
    out->violations=v;out->repairs=repairs;out->state_mask=state_mask(v);out->structural_mask=structural_mask(v);out->health=structural_score(v);out->energy=1.0-out->health;
    if(v==0&&repairs)out->decision=2;else if(v==0)out->decision=1;else out->decision=0;
    if(repaired&&repaired_cap){if(s.size()+1>repaired_cap)return -3;std::memcpy(repaired,s.data(),s.size());repaired[s.size()]='\0';}
    return 0;
}
