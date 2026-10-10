// MSN-GUARD — Android JNI bridge for Aether 2.3.0.
//
// The 2.3.0 FFI is job-shaped, not config-JSON-shaped. The engine exposes
// aether_core_start(arguments) which spawns crate::run_with(argv) as a job,
// and every option is read from the process environment (AETHER_*) exactly
// the way the fcae-ffi aether bridge does it (bridges/aether/src/lib.rs:
// `let args = CString::new("[]")` then wait for the SOCKS listener).
//
// The host therefore prepares AETHER_* before calling nativeStart, and this
// bridge only owns the job lifecycle:
//   start  -> aether_core_start("[]") on a worker thread, job id stored
//   stop   -> aether_job_cancel + aether_job_free
//   events -> the engine logs through env_logger to logcat (LOG_TAG MSN_AETHER)
#include <jni.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>

#include <android/log.h>

#define LOG_TAG "MSN_AETHER"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C" {
const char* aether_version();
const char* aether_core_start(const char* arguments);
const char* aether_job_poll(unsigned long long id);
const char* aether_job_cancel(unsigned long long id);
const char* aether_job_free(unsigned long long id);
const char* aether_stats_snapshot();
void aether_string_free(const char* raw);
void aether_set_log_sink(void (*callback)(const char* line));
}

namespace {

// The job id of the running tunnel. 0 means none. Set on the caller's thread
// once aether_core_start replies, cleared by stop() or by the worker thread
// when the job reports it is done.
std::mutex g_job_mu;
unsigned long long g_job = 0;

JavaVM* g_vm = nullptr;
jobject g_service = nullptr;
jmethodID g_on_event = nullptr;
jmethodID g_on_log = nullptr;
std::mutex g_service_mutex;

// The engine's log relay. PattNG reads the core's stdout line by line; an
// in-process library has none, so the engine calls this for every log record
// and the host routes it to ConnectionLog. The signature is
// onEngineLog(String) on the service.
extern "C" JNIEXPORT void JNICALL
Java_com_msnguard_vpn_NativeCore_nativeSetLogSink(JNIEnv*, jobject) {
    // Looked up lazily: attach() may not have run when a test sets the sink.
    aether_set_log_sink([](const char* line) {
        JNIEnv* env = nullptr;
        bool attached = false;
        if (g_vm == nullptr) return;
        if (g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
            if (g_vm->AttachCurrentThread(&env, nullptr) != JNI_OK) return;
            attached = true;
        }
        {
            std::lock_guard<std::mutex> lock(g_service_mutex);
            if (g_service != nullptr && g_on_log != nullptr) {
                jstring jline = env->NewStringUTF(line);
                env->CallVoidMethod(g_service, g_on_log, jline);
                env->DeleteLocalRef(jline);
            }
        }
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        if (attached) g_vm->DetachCurrentThread();
    });
}


void on_event(const std::string& json) {
    JNIEnv* env = nullptr;
    bool attached = false;
    if (g_vm == nullptr) return;
    if (g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        if (g_vm->AttachCurrentThread(&env, nullptr) != JNI_OK) return;
        attached = true;
    }

    {
        std::lock_guard<std::mutex> lock(g_service_mutex);
        if (g_service != nullptr && g_on_event != nullptr) {
            jstring jjson = env->NewStringUTF(json.c_str());
            env->CallVoidMethod(g_service, g_on_event, jjson);
            env->DeleteLocalRef(jjson);
        }
    }

    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    if (attached) g_vm->DetachCurrentThread();
}

// True when the engine reports the job is no longer running.
bool job_finished(unsigned long long id) {
    if (id == 0) return true;
    const char* reply = aether_job_poll(id);
    if (reply == nullptr) return true;
    std::string text(reply);
    aether_string_free(reply);
    // {"state":"running"} | {"state":"done","result":{...}}
    return text.find("\"state\":\"done\"") != std::string::npos;
}

// Frees the job's registry entry. The SOCKS/HTTP listeners are owned by the
// task behind the job and go with it, so dropping the job tears them down.
void free_job(unsigned long long id) {
    const char* reply = aether_job_free(id);
    if (reply != nullptr) aether_string_free(reply);
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_msnguard_vpn_NativeCore_nativeVersion(JNIEnv* env, jobject) {
    const char* v = aether_version();
    std::string text(v ? v : "");
    if (v) aether_string_free(v);
    if (!text.empty()) LOGI("aether version: %s", text.c_str());
    return env->NewStringUTF(text.c_str());
}

// Pre-2.3.0 this ran identity/endpoint selection in-process and returned the
// tunnel addresses. 2.3.0 has no separate prepare step: aether_core_start
// loads or provisions the identity itself ("loaded existing warp identity
// from .../aether.toml") and scans inside the job. The host already points
// the engine at its files through AETHER_CONFIG, so this is a no-op that
// keeps the Kotlin call site compiling.
extern "C" JNIEXPORT jint JNICALL
Java_com_msnguard_vpn_NativeCore_nativePrepare(JNIEnv*, jobject, jstring) {
    return 0;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_msnguard_vpn_NativeCore_nativeLastResult(JNIEnv* env, jobject) {
    return env->NewStringUTF("");
}

extern "C" JNIEXPORT jint JNICALL
Java_com_msnguard_vpn_NativeCore_nativeRequestEmailCode(
    JNIEnv*, jobject, jstring, jstring) {
    return 0;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_msnguard_vpn_NativeCore_nativeConfirmEmailCode(
    JNIEnv*, jobject, jstring) {
    return 0;
}

// Blocks until the tunnel exits — call on a worker thread, as before.
extern "C" JNIEXPORT jint JNICALL
Java_com_msnguard_vpn_NativeCore_nativeStart(JNIEnv*, jobject, jstring, jint) {
    // 2.3.0 owns no TUN: it publishes a SOCKS5 listener (127.0.0.1:1819 by
    // default, AETHER_SOCKS to move it) and the host's TunEngine
    // (tun2socks/Hev/Zeptun) bridges the Android VPN interface to it — the
    // same split FCAE has between the aether backend and its TUN bridges.
    // tun_fd and the old config JSON are therefore unused; the whole engine
    // configuration comes from the AETHER_* environment the service sets.
    static std::thread::id g_starter;
    {
        std::lock_guard<std::mutex> lock(g_job_mu);
        if (g_job != 0) {
            LOGE("aether already running as job %llu", (unsigned long long)g_job);
            return -1;
        }
        g_starter = std::this_thread::get_id();
    }

    const char* reply = aether_core_start("[]");
    if (reply == nullptr) {
        LOGE("aether_core_start returned null");
        return -1;
    }
    std::string text(reply);
    aether_string_free(reply);

    // {"ok":true,"job":<id>} on success, {"ok":false,"error":"..."} on failure.
    if (text.find("\"ok\":false") != std::string::npos) {
        LOGE("aether_core_start failed: %s", text.c_str());
        return -1;
    }
    size_t at = text.find("\"job\":");
    if (at == std::string::npos) {
        LOGE("aether_core_start gave no job id: %s", text.c_str());
        return -1;
    }
    unsigned long long id = 0;
    sscanf(text.c_str() + at + 6, "%llu", &id);
    if (id == 0) {
        LOGE("aether_core_start gave job id 0: %s", text.c_str());
        return -1;
    }
    {
        std::lock_guard<std::mutex> lock(g_job_mu);
        g_job = id;
    }
    LOGI("aether_core_start -> job %llu", id);

    // Report the job's outcome from a detached thread. The engine logs its own
    // banner through env_logger, but when the job dies before logging anything
    // (a bad option, a bind failure, a panic) the host sees only -1. This
    // thread is what makes that visible without blocking start().
    std::thread([id]() {
        for (int i = 0; i < 600; i++) {  // up to 60s
            const char* probe = aether_job_poll(id);
            if (probe == nullptr) { LOGE("job %llu: poll returned null", id); return; }
            std::string seen(probe);
            aether_string_free(probe);
            if (seen.find("\"state\":\"done\"") != std::string::npos) {
                LOGE("job %llu finished: %s", id, seen.c_str());
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        LOGE("job %llu: still running after 60s", id);
    }).detach();

    // Non-blocking: return immediately. The tunnel keeps running until
    // nativeStop cancels the job. Polling is done by IsRunning / the
    // watchdog; the worker thread that called start is freed for UI /
    // notification / egress verification instead of being held for the
    // whole session like the old aether_start_json_with_tun was.
    return 0;
}

// TUN-less start: identical to nativeStart in 2.3.0. The engine always binds
// the SOCKS listener; the host decides whether to bridge a TUN to it. Used by
// Psiphon-over-WARP and the Shard front, which both dial 127.0.0.1:1819.
extern "C" JNIEXPORT jint JNICALL
Java_com_msnguard_vpn_NativeCore_nativeStartProxy(JNIEnv* env, jobject, jstring config) {
    return Java_com_msnguard_vpn_NativeCore_nativeStart(env, nullptr, config, -1);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_msnguard_vpn_NativeCore_nativeStop(JNIEnv*, jobject) {
    unsigned long long id = 0;
    {
        std::lock_guard<std::mutex> lock(g_job_mu);
        id = g_job;
    }
    if (id == 0) return 0;

    const char* reply = aether_job_cancel(id);
    if (reply != nullptr) aether_string_free(reply);
    // Wait for the job to actually reach Done. The SOCKS listener is owned by
    // the task behind the job; cancelling only signals the cancel token, so a
    // start() that immediately follows would find g_job != 0 ("aether already
    // running") and the listener still bound on the port the new one needs.
    // 300 ms is what an orderly shutdown takes; the poll below covers the rest.
    for (int i = 0; i < 30; i++) {
        const char* probe = aether_job_poll(id);
        if (probe == nullptr) break;
        std::string seen(probe);
        aether_string_free(probe);
        if (seen.find("\"state\":\"done\"") != std::string::npos) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    free_job(id);
    {
        std::lock_guard<std::mutex> lock(g_job_mu);
        if (g_job == id) g_job = 0;
    }
    return 0;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_msnguard_vpn_NativeCore_nativeIsRunning(JNIEnv*, jobject) {
    unsigned long long id;
    {
        std::lock_guard<std::mutex> lock(g_job_mu);
        id = g_job;
    }
    if (id == 0) return JNI_FALSE;
    if (job_finished(id)) {
        std::lock_guard<std::mutex> lock(g_job_mu);
        if (g_job == id) {
            free_job(id);
            g_job = 0;
        }
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_msnguard_vpn_NativeCore_nativeIsReady(JNIEnv* env, jobject) {
    return Java_com_msnguard_vpn_NativeCore_nativeIsRunning(env, nullptr);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_msnguard_vpn_NativeCore_nativeLastError(JNIEnv* env, jobject) {
    // 2.3.0 reports failure through the job registry, not a global string. A
    // dead job's reason is in its Done payload: {"state":"done","result":
    // {"ok":false,"error":"..."}}. Without this, a tunnel that exits with code
    // -1 showed the user a bare number and logcat showed nothing either, so a
    // registration failure looked identical to a port bind failure.
    unsigned long long id = 0;
    {
        std::lock_guard<std::mutex> lock(g_job_mu);
        id = g_job;
    }
    if (id == 0) return env->NewStringUTF("");
    const char* reply = aether_job_poll(id);
    if (reply == nullptr) return env->NewStringUTF("");
    std::string text(reply);
    aether_string_free(reply);
    if (text.find("\"ok\":false") == std::string::npos) return env->NewStringUTF("");
    // Extract the error message.
    size_t at = text.find("\"error\"");
    if (at == std::string::npos) return env->NewStringUTF(text.c_str());
    at = text.find('"', at + 7);
    if (at == std::string::npos) return env->NewStringUTF(text.c_str());
    size_t end = text.find('"', at + 1);
    if (end == std::string::npos) return env->NewStringUTF(text.c_str());
    return env->NewStringUTF(text.substr(at + 1, end - at - 1).c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_msnguard_vpn_NativeCore_nativeLastLog(JNIEnv* env, jobject) {
    // The engine logs to logcat through env_logger; lastLog was the old
    // in-process ring buffer and has no 2.3.0 equivalent. Returning empty
    // keeps the Kotlin call site working; logcat (tag MSN_AETHER) is the log.
    return env->NewStringUTF("");
}

extern "C" JNIEXPORT void JNICALL
Java_com_msnguard_vpn_NativeCore_nativeSetEnv(JNIEnv* env, jobject, jstring key, jstring value) {
    const char* k = env->GetStringUTFChars(key, nullptr);
    if (k == nullptr) return;
    const char* v = env->GetStringUTFChars(value, nullptr);
    if (v == nullptr) {
        env->ReleaseStringUTFChars(key, k);
        return;
    }
    // overwrite=1: a reconnect rewrites every option wholesale, so an old value
    // must never survive. setenv copies its input, so the jstrings can be
    // released immediately.
    setenv(k, v, 1);
    env->ReleaseStringUTFChars(value, v);
    env->ReleaseStringUTFChars(key, k);
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_com_msnguard_vpn_NativeCore_nativeStatsSnapshot(JNIEnv* env, jobject) {
    const char* raw = aether_stats_snapshot();
    if (raw == nullptr) {
        // 2.3.15: the engine is reachable but has no counters yet — log it so
        // a permanent zero in the UI points at the FFI and not at the poller.
        LOGI("aether_stats_snapshot returned null");
        return nullptr;
    }
    std::string text(raw);
    aether_string_free(raw);
    // {\"ok\":true,\"up\":N,\"down\":M} — json objects, small and cheap.
    auto findU64 = [&](const char* key) -> long long {
        std::string needle = std::string("\"") + key + "\":";
        size_t at = text.find(needle);
        if (at == std::string::npos) return 0;
        at += needle.size();
        long long v = 0;
        sscanf(text.c_str() + at, "%lld", &v);
        return v;
    };
    long long up = findU64("up");
    long long down = findU64("down");
    // 2.3.15: one logcat line per call makes a stuck counter visible in
    // logcat (tag MSN_AETHER) without the app having to be in debug mode.
    if (up == 0 && down == 0) {
        LOGI("aether stats snapshot: zero (payload=%s)", text.c_str());
    }
    jlongArray out = env->NewLongArray(2);
    if (out == nullptr) return nullptr;
    jlong vals[2] = { (jlong)up, (jlong)down };
    env->SetLongArrayRegion(out, 0, 2, vals);
    return out;
}

extern "C" JNIEXPORT void JNICALL
Java_com_msnguard_vpn_NativeCore_nativeAttach(JNIEnv* env, jobject, jobject service) {
    std::lock_guard<std::mutex> lock(g_service_mutex);
    if (g_service != nullptr) env->DeleteGlobalRef(g_service);
    g_service = env->NewGlobalRef(service);
    const jclass type = env->GetObjectClass(service);
    g_on_event = env->GetMethodID(type, "onEvent", "(Ljava/lang/String;)V");
    g_on_log = env->GetMethodID(type, "onEngineLog", "(Ljava/lang/String;)V");
    env->DeleteLocalRef(type);
}

extern "C" JNIEXPORT void JNICALL
Java_com_msnguard_vpn_NativeCore_nativeDetach(JNIEnv* env, jobject) {
    std::lock_guard<std::mutex> lock(g_service_mutex);
    if (g_service != nullptr) env->DeleteGlobalRef(g_service);
    g_service = nullptr;
    g_on_event = nullptr;
}

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void*) {
    g_vm = vm;
    return JNI_VERSION_1_6;
}
