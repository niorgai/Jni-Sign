#include <jni.h>
#include <string>
#include "map"
#include "MD5.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/document.h"
#include <android/log.h>
using namespace rapidjson;

#define TAG    "jni-test" // 这个是自定义的LOG的标识
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,TAG,__VA_ARGS__) // 定义LOGD类型

const char* salt = "salt";
const char* sign = "3082030d308201f5a003020102020449db7500300d06092a864886f70d01010b05003037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f6964204465627567301e170d3135303631373035343234335a170d3435303630393035343234335a3037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f696420446562756730820122300d06092a864886f70d01010105000382010f003082010a0282010100d6b4e0168ca0f3daefaee7ce2edb4411cc5ef3030f766774a6bb637ce998b25526c45c95040bf006049c8a49e6c3d8d698dcea7541ec2cdc10f0f6cb3210784a466a6fc87d0b881f7a8a50e2215a72d3a092d204de12fd2d2e7bc1053cc97cadd5ac2ef0bad9eae436e2d467eb93077b02de4eb7d0797db3d567e72980db70de457b9e09e50f74aec5781152fd43b1ed7589e86401a87ba32c22ae56a8949d3cac3ee9add5c973259edab5b8d996ad80751c81a51f5d3d1880af9687ea3d239999227674ffaf3c78d65ed190404d6975343e88a77a6ea521297ac5da9e67cb050df0ea03e191b85d455dba4530ad4e9bc930b4c3543f1e5ccd017f9da238f2b90203010001a321301f301d0603551d0e04160414227c0d03faf8382097130d0bd2135b9f8602b505300d06092a864886f70d01010b050003820101006b20d13ef5410d3ec28350aedb6d8858fedacfd871d13776c0e5a541d0c20d87124029289a68b946554872ec7a62edb82d4d722e2aae8def276251c0ea50ad36b996866993105a740faa3072ec6f1d2acf0ffc34d73a0ad6b6d04c8c08d82e9b89900de10f78fbc8b359f8bb30af7dc7300004ca053b3f230c1fe1dfc83586fa6173ee8f35b7ba906e1f2649a9c53007a6b824425952d26d070ac7d211c552dab94398292c83382b45a0d0a645ea92cb8a7fa4c851ee295bedc350cf52b6377e072c5ca1d787f4593ac5b9e6c6b70fc372c1eb9cfb596a3d45e4de182866b9e0d1bfd7f56a05780a7d8ba0dc7432475150c98f6ca37c696ed9d2e0928b316e29";

bool checkPackageSignature(JNIEnv *env, jobject context) {
    jclass ctxClazz = env->GetObjectClass(context);
    //获取 PackageName
    jmethodID mId = env->GetMethodID(ctxClazz, "getPackageName", "()Ljava/lang/String;");
    jstring pkgName = static_cast<jstring>(env->CallObjectMethod(context, mId));

    //获取 PackageManager
    jmethodID getPmId = env->GetMethodID(ctxClazz, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject packageManager = env->CallObjectMethod(context, getPmId);
    jclass pkgClazz = env->GetObjectClass(packageManager);

    //获取 PackageInfo
    jmethodID pkgInfoId = env->GetMethodID(pkgClazz, "getPackageInfo","(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jobject pkgInfo = env->CallObjectMethod(packageManager, pkgInfoId, pkgName, 0x00000040);
    jclass pkgInfoClazz = env->GetObjectClass(pkgInfo);

    //获取 Signature 数组
    jfieldID signsFieldId = env->GetFieldID(pkgInfoClazz, "signatures", "[Landroid/content/pm/Signature;");
    jobject signs = env->GetObjectField(pkgInfo, signsFieldId);
    jobjectArray signaturesArray = (jobjectArray)signs;

    //获取第一个 Signature
    jobject firstSign = env->GetObjectArrayElement(signaturesArray, 0);
    jclass signClazz = env->GetObjectClass(firstSign);
    jmethodID toStringId = env->GetMethodID(signClazz, "toCharsString", "()Ljava/lang/String;");

    //转为 string
    jstring str = static_cast<jstring>(env->CallObjectMethod(firstSign, toStringId));
    char *c_msg = (char*)env->GetStringUTFChars(str,0);

    LOGD("the signature of this apk is : %s", c_msg);
    return (strcmp(c_msg, sign) == 0);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_libnet_Utils_getSign(JNIEnv *env, jobject instance, jobject context, jobject params) {
    if (!checkPackageSignature(env, context)) {
        return env->NewStringUTF("the signature is not the same.");
    }

    jclass mapClass = env->GetObjectClass(params);
    jmethodID getId = env->GetMethodID(mapClass, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    //获取 keySet
    jmethodID keySets = env->GetMethodID(mapClass, "keySet", "()Ljava/util/Set;");
    jobject keys = env->CallObjectMethod(params, keySets);
    jclass setClass = env->GetObjectClass(keys);
    //转为 数组
    jmethodID toArrId = env->GetMethodID(setClass, "toArray", "()[Ljava/lang/Object;");
    jobjectArray keyArr = static_cast<jobjectArray>(env->CallObjectMethod(keys, toArrId));
    jsize keySize = env->GetArrayLength(keyArr);

    //放入 map
    std::map<std::string, std::string> map;
    for (int i = 0; i < keySize; ++i) {
        jstring jkey = (jstring)env->GetObjectArrayElement(keyArr, i);
        jstring jvalue = (jstring)env->CallObjectMethod(params, getId, jkey);
        char* key = (char*)env->GetStringUTFChars(jkey,0);
        char* value = (char*)env->GetStringUTFChars(jvalue,0);
        map[key] = value;
    }

    //编译为 json
    Document document;
    Document::AllocatorType& allocator = document.GetAllocator();
    Value root(kObjectType);

    Value key(kStringType);
    Value value(kStringType);

    std::map<std::string, std::string>::iterator it = map.begin();
    while (it != map.end()) {
        key.SetString(it->first.c_str(), allocator);
        value.SetString(it->second.c_str(), allocator);
        root.AddMember(key, value, allocator);
        ++ it;
    }
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    root.Accept(writer);
    std::string paramString = buffer.GetString();
    LOGD("after change to json, ans is  %s", paramString.c_str());

    //MD5
    MD5 md5 = MD5(paramString);
    paramString = md5.hexdigest();
    LOGD("after MD5, ans is %s", paramString.c_str());

    return env->NewStringUTF(paramString.c_str());
}

