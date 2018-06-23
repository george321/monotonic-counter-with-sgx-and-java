package LibSgxJava;

public class SgxFunction {
    static {
        System.loadLibrary("Sgx");
    }

    /* Initialize the enclave */
    public native int jni_initialize_enclave(int id);

    /* Ecall create_counter in enclave */
    public native void jni_ecall_sgx_create_counter();

    /* Ecall read_counter in enclave */
    public native int jni_ecall_sgx_read_counter();

    /* Ecall increment_counter in enclave */
    public native void jni_ecall_sgx_increment_counter();

    /* Destroy the enclave */
    public native void jni_sgx_destroy_enclave();
}
