#include <jni.h>

#include <mutex>
#include <string>

extern "C" {
int aether_prepare_json(const char* json);
const char* aether_last_result();
int aether_start_json(const char* json);
int aether_start_json_with_tun(const char* json, int tun_fd);
int aether_stop();
int aether_is_running();
int aether_is_ready();
const char* aether_last_error();
const char* aether_last_log();
void aether_set_socket_protector(int (*protector)(int));
}

namespace {
JavaVM* g_vm = nullptr;
jobject g_service = nullptr;
jmethodID g_protect_socket = nullptr;
std::mutex g_service_mutex;

std::string copy_jstring(JNIEnv* env, jstring value) {
    if (value == nullptr) return {};
    const char* chars = env->GetStringUTFChars(value, nullptr);
    if (chars == nullptr) return {};
    std::string result(chars);
    env->ReleaseStringUTFChars(value, chars);
    return result;
}

int protect_socket(int fd) {
    JNIEnv* env = nullptr;
    bool attached = false;
    if (g_vm == nullptr) return 0;
    if (g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        if (g_vm->AttachCurrentThread(&env, nullptr) != JNI_OK) return 0;
        attached = true;
    }

    std::lock_guard<std::mutex> lock(g_service_mutex);
    const auto protected_socket = g_service != nullptr && g_protect_socket != nullptr &&
        env->CallBooleanMethod(g_service, g_protect_socket, fd);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        if (attached) g_vm->DetachCurrentThread();
        return 0;
    }
    if (attached) g_vm->DetachCurrentThread();
    return protected_socket ? 1 : 0;
}

jstring last_string(JNIEnv* env, const char* value) {
    return env->NewStringUTF(value == nullptr ? "" : value);
}
}  // namespace

extern "C" JNIEXPORT jint JNICALL
Java_studio_cluvex_aethery_NativeCore_nativePrepare(JNIEnv* env, jobject, jstring config) {
    const auto config_text = copy_jstring(env, config);
    if (config_text.empty()) return -1;
    const int code = aether_prepare_json(config_text.c_str());
    return code;
}

extern "C" JNIEXPORT jstring JNICALL
Java_studio_cluvex_aethery_NativeCore_nativeLastResult(JNIEnv* env, jobject) {
    return last_string(env, aether_last_result());
}

extern "C" JNIEXPORT jint JNICALL
Java_studio_cluvex_aethery_NativeCore_nativeStart(JNIEnv* env, jobject, jstring config, jint tun_fd) {
    const auto config_text = copy_jstring(env, config);
    if (config_text.empty()) return -1;
    return aether_start_json_with_tun(config_text.c_str(), tun_fd);
}

extern "C" JNIEXPORT jint JNICALL
Java_studio_cluvex_aethery_NativeCore_nativeStartProxy(JNIEnv* env, jobject, jstring config) {
    const auto config_text = copy_jstring(env, config);
    if (config_text.empty()) return -1;
    return aether_start_json(config_text.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_studio_cluvex_aethery_NativeCore_nativeStop(JNIEnv*, jobject) {
    return aether_stop();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_studio_cluvex_aethery_NativeCore_nativeIsRunning(JNIEnv*, jobject) {
    return aether_is_running() != 0;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_studio_cluvex_aethery_NativeCore_nativeIsReady(JNIEnv*, jobject) {
    return aether_is_ready() != 0;
}


extern "C" JNIEXPORT jstring JNICALL
Java_studio_cluvex_aethery_NativeCore_nativeLastError(JNIEnv* env, jobject) {
    return last_string(env, aether_last_error());
}

extern "C" JNIEXPORT jstring JNICALL
Java_studio_cluvex_aethery_NativeCore_nativeLastLog(JNIEnv* env, jobject) {
    return last_string(env, aether_last_log());
}

extern "C" JNIEXPORT void JNICALL
Java_studio_cluvex_aethery_NativeCore_nativeAttach(JNIEnv* env, jobject, jobject service) {
    std::lock_guard<std::mutex> lock(g_service_mutex);
    if (g_service != nullptr) env->DeleteGlobalRef(g_service);
    g_service = env->NewGlobalRef(service);
    const jclass type = env->GetObjectClass(service);
    g_protect_socket = env->GetMethodID(type, "protectSocket", "(I)Z");
    env->DeleteLocalRef(type);
    aether_set_socket_protector(protect_socket);
}

extern "C" JNIEXPORT void JNICALL
Java_studio_cluvex_aethery_NativeCore_nativeDetach(JNIEnv* env, jobject) {
    std::lock_guard<std::mutex> lock(g_service_mutex);
    aether_set_socket_protector(nullptr);
    if (g_service != nullptr) env->DeleteGlobalRef(g_service);
    g_service = nullptr;
    g_protect_socket = nullptr;
}

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void*) {
    g_vm = vm;
    return JNI_VERSION_1_6;
}
