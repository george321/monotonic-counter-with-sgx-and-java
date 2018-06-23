import LibSgxJava.*;

class JavaApp {
public static void main(String args[]){

        SgxFunction sgxFunctionTest = new SgxFunction();

        /*Initialize enclave */
        int initEnclaveStat = -1;
        initEnclaveStat = sgxFunctionTest.jni_initialize_enclave(1);
        if (initEnclaveStat < 0) {
                System.out.print("Failed to initiate enclave! Exiting...");
                return;
        }
        System.out.println("Successfully initialized enclave!");

        /*Generate a monotonic counter */
        /*Calling the sgx_create_counter function */


        sgxFunctionTest.jni_ecall_sgx_create_counter();
        System.out.print("Successfully created monotonic counter! "+"\n");


        int counter =  sgxFunctionTest.jni_ecall_sgx_read_counter();
        System.out.println("Counter = " + counter);

        sgxFunctionTest.jni_ecall_sgx_increment_counter();
        counter=  sgxFunctionTest.jni_ecall_sgx_read_counter();
        System.out.println("Counter = "+ counter);

        sgxFunctionTest.jni_ecall_sgx_increment_counter();
        counter=  sgxFunctionTest.jni_ecall_sgx_read_counter();
        System.out.println("Counter = "+ counter);


        sgxFunctionTest.jni_ecall_sgx_increment_counter();
        counter=  sgxFunctionTest.jni_ecall_sgx_read_counter();
        System.out.println("Counter = "+ counter);

        /*Destroy the enclave */
        sgxFunctionTest.jni_sgx_destroy_enclave();
}
}
