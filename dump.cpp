#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

#include "il2cpp-tabledefs.h"
#include "il2cpp-class.h"

#define DO_API(r, n, p) r (*n) p

#include "il2cpp-api-functions.h"

#undef DO_API

typedef void* (*dlsym_t)(void *handle, const char *symbol, const void* caller_addr);

int dump_fd = 2;

char buf[64 * 1024 * 1024];
size_t buf_pos = 0;

void _uprint(int fd, const char* format, ...) {
    char buffer[4096];
    va_list args;
    va_start(args, format);
    auto n = vsnprintf(buffer, 4096, format, args);
    va_end(args);
    if (fd == dump_fd) {
        memcpy(&buf[buf_pos], buffer, n);
        buf_pos += n;
    } else {
        write(fd, buffer, n);
    }
}

#define uprint(...) _uprint(2, __VA_ARGS__)

uint64_t _il2cpp_base = 0;
dlsym_t _dlsym = 0;

void init_il2cpp_api() {
#define DO_API(r, n, p) {                      \
    n = (r (*) p)_dlsym(NULL, #n, (void*)_il2cpp_base); \
    if(!n) {                                   \
        uprint("api not found %s\n", #n);          \
    }                                          \
}

#include "il2cpp-api-functions.h"

#undef DO_API
}

struct Dump {
    const Dump& operator <<(const char* str) const {
        _uprint(dump_fd, "%s", str);
        return *this;
    }

    const Dump& operator <<(unsigned long val) const {
        _uprint(dump_fd, "%lu", val);
        return *this;
    }
    const Dump& operator <<(long val) const {
        _uprint(dump_fd, "%ld", val);
        return *this;
    }
};

const Dump dump{};

void get_method_modifier(uint32_t flags) {
    auto access = flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;
    switch (access) {
        case METHOD_ATTRIBUTE_PRIVATE:
            dump << "private ";
            break;
        case METHOD_ATTRIBUTE_PUBLIC:
            dump << "public ";
            break;
        case METHOD_ATTRIBUTE_FAMILY:
            dump << "protected ";
            break;
        case METHOD_ATTRIBUTE_ASSEM:
        case METHOD_ATTRIBUTE_FAM_AND_ASSEM:
            dump << "internal ";
            break;
        case METHOD_ATTRIBUTE_FAM_OR_ASSEM:
            dump << "protected internal ";
            break;
    }
    if (flags & METHOD_ATTRIBUTE_STATIC) {
        dump << "static ";
    }
    if (flags & METHOD_ATTRIBUTE_ABSTRACT) {
        dump << "abstract ";
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) {
            dump << "override ";
        }
    } else if (flags & METHOD_ATTRIBUTE_FINAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) {
            dump << "sealed override ";
        }
    } else if (flags & METHOD_ATTRIBUTE_VIRTUAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_NEW_SLOT) {
            dump << "virtual ";
        } else {
            dump << "override ";
        }
    }
    if (flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) {
        dump << "extern ";
    }
}

bool _il2cpp_type_is_byref(const Il2CppType *type) {
    auto byref = type->byref;
    if (il2cpp_type_is_byref) {
        byref = il2cpp_type_is_byref(type);
    }
    return byref;
}

void dump_method(Il2CppClass *klass) {
    dump << "\n\t// Methods\n";
    void *iter = nullptr;
    while (auto method = il2cpp_class_get_methods(klass, &iter)) {
        //TODO attribute
        if (method->methodPointer) {
            dump << "\t// RVA: 0x";
            // dump << (uint64_t) method->methodPointer - il2cpp_base;
            _uprint(dump_fd, "%lx", (uint64_t) method->methodPointer - _il2cpp_base);
            dump << " VA: 0x";
            // dump << (uint64_t) method->methodPointer;
            _uprint(dump_fd, "%lx", (uint64_t) method->methodPointer);
        } else {
            dump << "\t// RVA: 0x VA: 0x0";
        }
        /*if (method->slot != 65535) {
            outPut << " Slot: " << std::dec << method->slot;
        }*/
        dump << "\n\t";
        uint32_t iflags = 0;
        auto flags = il2cpp_method_get_flags(method, &iflags);
        get_method_modifier(flags);
        //TODO genericContainerIndex
        auto return_type = il2cpp_method_get_return_type(method);
        if (_il2cpp_type_is_byref(return_type)) {
            dump << "ref ";
        }
        auto return_class = il2cpp_class_from_type(return_type);
        dump << il2cpp_class_get_name(return_class) << " " << il2cpp_method_get_name(method)
               << "(";
        auto param_count = il2cpp_method_get_param_count(method);
        for (int i = 0; i < param_count; ++i) {
            auto param = il2cpp_method_get_param(method, i);
            auto attrs = param->attrs;
            if (_il2cpp_type_is_byref(param)) {
                if (attrs & PARAM_ATTRIBUTE_OUT && !(attrs & PARAM_ATTRIBUTE_IN)) {
                    dump << "out ";
                } else if (attrs & PARAM_ATTRIBUTE_IN && !(attrs & PARAM_ATTRIBUTE_OUT)) {
                    dump << "in ";
                } else {
                    dump << "ref ";
                }
            } else {
                if (attrs & PARAM_ATTRIBUTE_IN) {
                    dump << "[In] ";
                }
                if (attrs & PARAM_ATTRIBUTE_OUT) {
                    dump << "[Out] ";
                }
            }
            auto parameter_class = il2cpp_class_from_type(param);
            dump << il2cpp_class_get_name(parameter_class) << " "
                   << il2cpp_method_get_param_name(method, i);
            dump << ", ";
        }
        // if (param_count > 0) {
        //     outPut.seekp(-2, outPut.cur);
        // }
        dump << ") { }\n";
        //TODO GenericInstMethod
    }
}

void dump_property(Il2CppClass *klass) {
    dump << "\n\t// Properties\n";
    void *iter = nullptr;
    while (auto prop_const = il2cpp_class_get_properties(klass, &iter)) {
        //TODO attribute
        auto prop = const_cast<PropertyInfo *>(prop_const);
        auto get = il2cpp_property_get_get_method(prop);
        auto set = il2cpp_property_get_set_method(prop);
        auto prop_name = il2cpp_property_get_name(prop);
        dump << "\t";
        Il2CppClass *prop_class = nullptr;
        uint32_t iflags = 0;
        if (get) {
            get_method_modifier(il2cpp_method_get_flags(get, &iflags));
            prop_class = il2cpp_class_from_type(il2cpp_method_get_return_type(get));
        } else if (set) {
            get_method_modifier(il2cpp_method_get_flags(set, &iflags));
            auto param = il2cpp_method_get_param(set, 0);
            prop_class = il2cpp_class_from_type(param);
        }
        if (prop_class) {
            dump << il2cpp_class_get_name(prop_class) << " " << prop_name << " { ";
            if (get) {
                dump << "get; ";
            }
            if (set) {
                dump << "set; ";
            }
            dump << "}\n";
        } else {
            if (prop_name) {
                dump << " // unknown property " << prop_name;
            }
        }
    }
}

void dump_field(Il2CppClass *klass) {
    dump << "\n\t// Fields\n";
    auto is_enum = il2cpp_class_is_enum(klass);
    void *iter = nullptr;
    while (auto field = il2cpp_class_get_fields(klass, &iter)) {
        //TODO attribute
        dump << "\t";
        auto attrs = il2cpp_field_get_flags(field);
        auto access = attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;
        switch (access) {
            case FIELD_ATTRIBUTE_PRIVATE:
                dump << "private ";
                break;
            case FIELD_ATTRIBUTE_PUBLIC:
                dump << "public ";
                break;
            case FIELD_ATTRIBUTE_FAMILY:
                dump << "protected ";
                break;
            case FIELD_ATTRIBUTE_ASSEMBLY:
            case FIELD_ATTRIBUTE_FAM_AND_ASSEM:
                dump << "internal ";
                break;
            case FIELD_ATTRIBUTE_FAM_OR_ASSEM:
                dump << "protected internal ";
                break;
        }
        if (attrs & FIELD_ATTRIBUTE_LITERAL) {
            dump << "const ";
        } else {
            if (attrs & FIELD_ATTRIBUTE_STATIC) {
                dump << "static ";
            }
            if (attrs & FIELD_ATTRIBUTE_INIT_ONLY) {
                dump << "readonly ";
            }
        }
        auto field_type = il2cpp_field_get_type(field);
        auto field_class = il2cpp_class_from_type(field_type);
        dump << il2cpp_class_get_name(field_class) << " " << il2cpp_field_get_name(field);
        //TODO 获取构造函数初始化后的字段值
        if (attrs & FIELD_ATTRIBUTE_LITERAL && is_enum) {
            uint64_t val = 0;
            il2cpp_field_static_get_value(field, &val);
            dump << " = " << val;
        }
        dump << "; // 0x";
        _uprint(dump_fd, "%lx", il2cpp_field_get_offset(field));
        dump << "\n";
    }
}

void dump_type(const Il2CppType *type) {
    auto *klass = il2cpp_class_from_type(type);
    dump << "\n// Namespace: " << il2cpp_class_get_namespace(klass) << "\n";
    auto flags = il2cpp_class_get_flags(klass);
    if (flags & TYPE_ATTRIBUTE_SERIALIZABLE) {
        dump << "[Serializable]\n";
    }
    //TODO attribute
    auto is_valuetype = il2cpp_class_is_valuetype(klass);
    auto is_enum = il2cpp_class_is_enum(klass);
    auto visibility = flags & TYPE_ATTRIBUTE_VISIBILITY_MASK;
    switch (visibility) {
        case TYPE_ATTRIBUTE_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_PUBLIC:
            dump << "public ";
            break;
        case TYPE_ATTRIBUTE_NOT_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:
        case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:
            dump << "internal ";
            break;
        case TYPE_ATTRIBUTE_NESTED_PRIVATE:
            dump << "private ";
            break;
        case TYPE_ATTRIBUTE_NESTED_FAMILY:
            dump << "protected ";
            break;
        case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM:
            dump << "protected internal ";
            break;
    }
    if (flags & TYPE_ATTRIBUTE_ABSTRACT && flags & TYPE_ATTRIBUTE_SEALED) {
        dump << "static ";
    } else if (!(flags & TYPE_ATTRIBUTE_INTERFACE) && flags & TYPE_ATTRIBUTE_ABSTRACT) {
        dump << "abstract ";
    } else if (!is_valuetype && !is_enum && flags & TYPE_ATTRIBUTE_SEALED) {
        dump << "sealed ";
    }
    if (flags & TYPE_ATTRIBUTE_INTERFACE) {
        dump << "interface ";
    } else if (is_enum) {
        dump << "enum ";
    } else if (is_valuetype) {
        dump << "struct ";
    } else {
        dump << "class ";
    }
    dump << il2cpp_class_get_name(klass); //TODO genericContainerIndex

    dump << " : ";
    
    auto parent = il2cpp_class_get_parent(klass);
    if (!is_valuetype && !is_enum && parent) {
        auto parent_type = il2cpp_class_get_type(parent);
        if (parent_type->type != IL2CPP_TYPE_OBJECT) {
            dump << il2cpp_class_get_namespace(klass) << "." << il2cpp_class_get_name(parent) << ",";
        }
    }
    void *iter = nullptr;
    while (auto itf = il2cpp_class_get_interfaces(klass, &iter)) {
        dump << (il2cpp_class_get_name(itf)) << ",";
    }
    
    dump << "\n{";
    dump_field(klass);
    dump_property(klass);
    dump_method(klass);
    //TODO EventInfo
    dump << "}\n";
}

extern "C" void pthread_atfork() {  }
extern "C" int atexit(void (*function)(void)) { return 0; }

extern "C"
int entry(dlsym_t dlsym, uintptr_t il2cpp_base)
{
    _dlsym = dlsym;
    _il2cpp_base = il2cpp_base;
    uprint("payload dlsym %p\n", dlsym);

    void* x = _dlsym(NULL, "", (void*)_il2cpp_base);
    uprint("payload dlsym %p\n", dlsym);

    dump_fd = open("/dump.cs", O_RDWR | O_CREAT, 0777);

    init_il2cpp_api();

    auto domain = il2cpp_domain_get();
    il2cpp_thread_attach(domain);

    uprint("ready\n");

    size_t size;
    auto assemblies = il2cpp_domain_get_assemblies(domain, &size);
    
    for (int i = 0; i < size; ++i) {
        auto image = il2cpp_assembly_get_image(assemblies[i]);
        // imageOutput << "// Image " << i << ": " << il2cpp_image_get_name(image) << "\n";
        uprint("// Image %d: %s\n", i, il2cpp_image_get_name(image));
    }

    auto corlib = il2cpp_get_corlib();
    auto assemblyClass = il2cpp_class_from_name(corlib, "System.Reflection", "Assembly");
    auto assemblyLoad = il2cpp_class_get_method_from_name(assemblyClass, "Load", 1);
    auto assemblyGetTypes = il2cpp_class_get_method_from_name(assemblyClass, "GetTypes", 0);
    if (assemblyLoad && assemblyLoad->methodPointer) {
        uprint("Assembly::Load: %p\n", assemblyLoad->methodPointer);
    } else {
        uprint("miss Assembly::Load\n");
        return 0;
    }
    if (assemblyGetTypes && assemblyGetTypes->methodPointer) {
        uprint("Assembly::GetTypes: %p\n", assemblyGetTypes->methodPointer);
    } else {
        uprint("miss Assembly::GetTypes\n");
        return 0;
    }
    typedef void *(*Assembly_Load_ftn)(void *, Il2CppString *, void *);
    typedef Il2CppArray *(*Assembly_GetTypes_ftn)(void *, void *);

    for (int i = 0; i < size; ++i) {
        auto image = il2cpp_assembly_get_image(assemblies[i]);
        // std::stringstream imageStr;
        auto image_name = il2cpp_image_get_name(image);
        // imageStr << "\n// Dll : " << image_name;
        //LOGD("image name : %s", image->name);
        // auto imageName = std::string(image_name);
        // auto pos = imageName.rfind('.');
        // auto imageNameNoExt = imageName.substr(0, pos);
        char imageNameNoExt[128];
        const char* end = strrchr(image_name, '.');
        memcpy(imageNameNoExt, image_name, end - image_name);
        imageNameNoExt[end - image_name] = 0;
        auto assemblyFileName = il2cpp_string_new(imageNameNoExt);
        uprint("Dump %s %d/%d\n", imageNameNoExt, i, size);
        // auto reflectionAssembly = ((Assembly_Load_ftn) assemblyLoad->methodPointer)(nullptr,
        //                                                                             assemblyFileName,
        //                                                                             nullptr);
        void* args[] = { assemblyFileName, NULL };
        Il2CppException *exc = NULL;
        auto* reflectionAssembly = il2cpp_runtime_invoke(assemblyLoad, assemblyClass, args, &exc);
        auto reflectionTypes = ((Assembly_GetTypes_ftn) assemblyGetTypes->methodPointer)(
                reflectionAssembly, nullptr);
        auto items = reflectionTypes->vector;
        for (int j = 0; j < reflectionTypes->max_length; ++j) {
            auto klass = il2cpp_class_from_system_type((Il2CppReflectionType *) items[j]);
            auto type = il2cpp_class_get_type(klass);
            // uprint("[x] type name : %s\n", il2cpp_type_get_name(type));
            dump_type(type);
            // auto outPut = imageStr.str() + dump_type(type);
            // outPuts.push_back(outPut);
        }
    }
    write(dump_fd, buf, buf_pos);
    close(dump_fd);
    uprint("done...\n");
    return 0;
}
