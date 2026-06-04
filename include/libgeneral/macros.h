#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

namespace tihmstar {
    class exception {
    public:
        exception(const char *msg): _msg(msg) {}
        const char* what() const noexcept { return _msg; }
    private:
        const char* _msg;
    };
}

// retassure: check expression or throw
#define retassure(expr, msg) do { if(!(expr)) { fprintf(stderr, "Assertion failed: %s\n", msg); throw tihmstar::exception(msg); } } while(0)
#define assure(expr) do { if(!(expr)) { fprintf(stderr, "Assertion failed: %s\n", #expr); throw tihmstar::exception(#expr); } } while(0)

// reterror: printf to stderr and throw
#define reterror(fmt, ...) do { fprintf(stderr, "ERROR: " fmt "\n", ##__VA_ARGS__); throw tihmstar::exception("error"); } while(0)

// safeFree macros
#define safeFree(p) do { if(p){ free(p); p = NULL; } } while(0)
#define safeFreeCustom(p, fn) do { if(p){ fn(p); p = NULL; } } while(0)

// simple scope guard
template<typename F>
struct _ScopeGuard { F f; _ScopeGuard(F&& f):f(f){} ~_ScopeGuard(){ try{ f(); } catch(...){} } };
#define cleanup(x) auto CONCAT_SCOPE_GUARD = _ScopeGuard<decltype(x)>(x)

// helper to create unique variable name
#define _CONCAT(a,b) a##b
#define CONCAT_SCOPE_GUARD _CONCAT(_scope_guard_, __LINE__)

// MAINFUNCTION wrapper
#define MAINFUNCTION int main(int argc, const char * argv[]) { try { return main_r(argc, argv); } catch (tihmstar::exception &e) { fprintf(stderr, "Fatal error: %s\n", e.what()); return 1; } }
