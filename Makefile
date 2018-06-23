######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

######## Java Settings ########
Java_App_Name := JavaApp.class
Java_App := $(Java_App_Name:.class=)

######## Library Settings ########

     ## LibSgxJava ##
LibSgxJava_Java_Files := $(wildcard LibSgxJava/*.java)
LibSgxJava_Java_Classes := $(LibSgxJava_Java_Files:.java=.class)
Jni_Flags := -I/usr/lib/jvm/java-8-oracle/include/ -I/usr/lib/jvm/java-8-oracle/include/linux

     ## LibSgxJni ##
LibSgxJni_Cpp_Files := $(wildcard LibSgxJni/*.cpp)
LibSgxJni_Cpp_Objects := $(LibSgxJni_Cpp_Files:.cpp=.o)
SGX_Library_Name := libSgx.so

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

LibSgxJni_Include_Paths := -I$(SGX_SDK)/include

LibSgxJni_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(LibSgxJni_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        LibSgxJni_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        LibSgxJni_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        LibSgxJni_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

LibSgxJni_Cpp_Flags := $(LibSgxJni_C_Flags) -std=c++11
LibSgxJni_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread

ifneq ($(SGX_MODE), HW)
	Uae_Library_Name = sgx_uae_service_sim
	LibSgxJni_Link_Flags += -lsgx_uae_service_sim
else
	Uae_Library_Name = sgx_uae_service
	LibSgxJni_Link_Flags += -lsgx_uae_service
endif

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := Enclave/Enclave.cpp $(wildcard Enclave/Edger8rSyntax/*.cpp) $(wildcard Enclave/TrustedLibrary/*.cpp) Enclave/Sealing/Sealing.cpp
Enclave_Include_Paths := -IInclude -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=Enclave/Enclave.lds

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: .config_$(Build_Mode)_$(SGX_ARCH) $(Java_App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(Java_App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: .config_$(Build_Mode)_$(SGX_ARCH) $(SGX_Library_Name) $(Java_App_Name) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@java $(Java_App)
	@echo "RUN  =>  $(Java_App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif


######## Java App Classes ########
JavaApp.class: JavaApp/JavaApp.java $(LibSgxJava_Java_Classes)
	@javac -d . -g JavaApp/JavaApp.java
	@echo "Gen  =>  $@"

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f .config_* $(Java_App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(LibSgxJni_Cpp_Objects) LibSgxJni/Enclave_u.*  LibSgxJni/*.so $(Enclave_Cpp_Objects) Enclave/Enclave_t.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)


######## Lib Objects ########

     ## LibSgxJava ##
$(LibSgxJava_Java_Classes): $(LibSgxJava_Java_Files)
	@javac -g $<

     ## LibSgxJni ##
LibSgxJni/Enclave_u.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd LibSgxJni && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

LibSgxJni/Enclave_u.o: LibSgxJni/Enclave_u.c
	@$(CC) $(LibSgxJni_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

LibSgxJni/%.o: $(LibSgxJni_Cpp_Files)
	@$(CXX) $(LibSgxJni_Cpp_Flags) $(Jni_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(SGX_Library_Name): LibSgxJni/Enclave_u.o $(LibSgxJni_Cpp_Objects)
	@$(CXX) -shared -o $(SGX_Library_Name) LibSgxJni/Enclave_u.o $(LibSgxJni_Cpp_Objects) -L$(SGX_LIBRARY_PATH) -l$(Uae_Library_Name) -l$(Urts_Library_Name)
	@echo "GEN  =>  $@"

######## Enclave Objects ########

Enclave/Enclave_t.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f .config_* $(Java_App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(LibSgxJni_Cpp_Objects) $(LibSgxJava_Java_Classes) LibSgxJni/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.* *.so
