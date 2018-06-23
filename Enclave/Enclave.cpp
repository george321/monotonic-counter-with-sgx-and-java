#include "Enclave_t.h"

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_tae_service.h"

#include "string.h"


#define REPLAY_PROTECTED_SECRET_SIZE  32

typedef struct _monotonic_counter
{
  sgx_mc_uuid_t mc;
  uint32_t mc_value;
}monotonic_counter;


static uint32_t verify_mc(monotonic_counter* mc2verify)
{
  uint32_t ret = 0;
  uint32_t mc_value;
  ret = sgx_read_monotonic_counter(&mc2verify->mc, &mc_value);
  if (ret != SGX_SUCCESS)
  {
    switch (ret)
    {
    case SGX_ERROR_SERVICE_UNAVAILABLE:
      /* Architecture Enclave Service Manager is not installed or not
      working properly.*/
      break;
    case SGX_ERROR_SERVICE_TIMEOUT:
      /* retry the operation later*/
      break;
    case SGX_ERROR_BUSY:
      /* retry the operation later*/
      break;
    case SGX_ERROR_MC_NOT_FOUND:
      /* the the Monotonic Counter ID is invalid.*/
      break;
    default:
      /*other errors*/
      break;
    }
  }
  else if (mc_value != mc2verify->mc_value)
  {
    ret = 0x002;
  }
  return ret;
}

static uint32_t read_and_verify_monotonic_counter(
  const sgx_sealed_data_t* mc2unseal,
  monotonic_counter* mc_unsealed)
{
  uint32_t ret = 0;
  monotonic_counter temp_unseal;
  uint32_t unseal_length = sizeof(monotonic_counter);

  ret = sgx_unseal_data(mc2unseal, NULL, 0,
    (uint8_t*)&temp_unseal, &unseal_length);
  if (ret != SGX_SUCCESS)
  {
    switch (ret)
    {
    case SGX_ERROR_MAC_MISMATCH:
      /* MAC of the sealed data is incorrect.
      The sealed data has been tampered.*/
      break;
    case SGX_ERROR_INVALID_ATTRIBUTE:
      /*Indicates attribute field of the sealed data is incorrect.*/
      break;
    case SGX_ERROR_INVALID_ISVSVN:
      /* Indicates isv_svn field of the sealed data is greater than
      the enclave's ISVSVN. This is a downgraded enclave.*/
      break;
    case SGX_ERROR_INVALID_CPUSVN:
      /* Indicates cpu_svn field of the sealed data is greater than
      the platform's cpu_svn. enclave is  on a downgraded platform.*/
      break;
    case SGX_ERROR_INVALID_KEYNAME:
      /*Indicates key_name field of the sealed data is incorrect.*/
      break;
    default:
      /*other errors*/
      break;
    }
    return ret;
  }
  ret = verify_mc(&temp_unseal);
  if (ret == SGX_SUCCESS)
    memcpy(mc_unsealed, &temp_unseal, sizeof(monotonic_counter));
  /* remember to clear secret data after been used by memset_s */
  memset_s(&temp_unseal, sizeof(monotonic_counter), 0,
    sizeof(monotonic_counter));
  return ret;
}

uint32_t get_size() {
  return sgx_calc_sealed_data_size(0, sizeof(monotonic_counter));
}

uint32_t create_sealed_monotonic_counter(uint8_t* sealed_mc_result, uint32_t sealed_mc_size)
{
  uint32_t ret = 0;
  int busy_retry_times = 2;
  monotonic_counter mc2seal;
  memset(&mc2seal, 0, sizeof(mc2seal));
  uint32_t size = sgx_calc_sealed_data_size(0,
    sizeof(monotonic_counter));
  if (sealed_mc_size != size)
    return SGX_ERROR_INVALID_PARAMETER;
  do {
    ret = sgx_create_pse_session();
  } while (ret == SGX_ERROR_BUSY && busy_retry_times--);
  if (ret != SGX_SUCCESS)
    return ret;
  do
  {
    ret = sgx_create_monotonic_counter(&mc2seal.mc, &mc2seal.mc_value);
    if (ret != SGX_SUCCESS)
    {
      switch (ret)
      {
      case SGX_ERROR_SERVICE_UNAVAILABLE:
        /* Architecture Enclave Service Manager is not installed or not
        working properly.*/
        break;
      case SGX_ERROR_SERVICE_TIMEOUT:
        /* retry the operation later*/
        break;
      case SGX_ERROR_BUSY:
        /* retry the operation later*/
        break;
      case SGX_ERROR_MC_OVER_QUOTA:
        /* SGX Platform Service enforces a quota scheme on the Monotonic
        Counters a SGX app can maintain. the enclave has reached the
        quota.*/
        break;
      case SGX_ERROR_MC_USED_UP:
        /* the Monotonic Counter has been used up and cannot create
        Monotonic Counter anymore.*/
        break;
      default:
        /*other errors*/
        break;
      }
      break;
    }

    /*sealing the plaintext to ciphertext. The ciphertext can be delivered
    outside of enclave.*/
    ret = sgx_seal_data(0, NULL, sizeof(mc2seal), (uint8_t*)&mc2seal,
      sealed_mc_size, (sgx_sealed_data_t*)sealed_mc_result);
  } while (0);

  /* remember to clear secret data after been used by memset_s */
  memset_s(&mc2seal, sizeof(monotonic_counter), 0,
    sizeof(monotonic_counter));
  sgx_close_pse_session();
  return ret;
}

uint32_t increment_monotonic_counter(uint8_t* sealed_mc_result, uint32_t sealed_mc_size)
{
  uint32_t ret = 0;
  int busy_retry_times = 2;
  monotonic_counter mc_unsealed;
  monotonic_counter mc2seal;
  do {
    ret = sgx_create_pse_session();
  } while (ret == SGX_ERROR_BUSY && busy_retry_times--);
  if (ret != SGX_SUCCESS)
    return ret;
  do
  {
    ret = read_and_verify_monotonic_counter((sgx_sealed_data_t*)sealed_mc_result,
      &mc_unsealed);
    if (ret != SGX_SUCCESS)
      break;

    memcpy(&mc2seal, &mc_unsealed, sizeof(monotonic_counter));

    ret = sgx_increment_monotonic_counter(&mc2seal.mc,
      &mc2seal.mc_value);
    if (ret != SGX_SUCCESS)
    {
      switch (ret)
      {
      case SGX_ERROR_SERVICE_UNAVAILABLE:
        /* Architecture Enclave Service Manager is not installed or not
        working properly.*/
        break;
      case SGX_ERROR_SERVICE_TIMEOUT:
        /* retry the operation*/
        break;
      case SGX_ERROR_BUSY:
        /* retry the operation later*/
        break;
      case SGX_ERROR_MC_NOT_FOUND:
        /* The Monotonic Counter was deleted or invalidated.
        This might happen under certain conditions.
        For example, the Monotonic Counter has been deleted, the SGX
        Platform Service lost its data or the system is under attack. */
        break;
      case SGX_ERROR_MC_NO_ACCESS_RIGHT:
        /* The Monotonic Counter is not accessible by this enclave.
        This might happen under certain conditions.
        For example, the SGX Platform Service lost its data or the
        system is under attack. */
        break;
      default:
        /*other errors*/
        break;
      }
      break;
    }

    /* If the counter value returns doesn't match the expected value,
    some other entity has updated the counter, for example, another instance
    of this enclave. The system might be under attack */
    if (mc2seal.mc_value != mc_unsealed.mc_value + 1)
    {
      ret = 0x002; //error
      break;
    }

    /* seal the incremented mc */
    ret = sgx_seal_data(0, NULL, sizeof(mc2seal), (uint8_t*)&mc2seal,
      sealed_mc_size, (sgx_sealed_data_t*)sealed_mc_result);
  } while (0);

  /* remember to clear secret data after been used by memset_s */
  memset_s(&mc_unsealed, sizeof(monotonic_counter), 0,
    sizeof(monotonic_counter));

  /* remember to clear secret data after been used by memset_s */
  memset_s(&mc2seal, sizeof(monotonic_counter), 0,
    sizeof(monotonic_counter));
  sgx_close_pse_session();
  return ret;
}

uint32_t read_sealed_monotonic_counter(uint8_t* sealed_mc_result, uint32_t sealed_mc_size, uint32_t* mc_value)
{
  uint32_t ret = 0;
  int busy_retry_times = 2;
  monotonic_counter mc_unsealed;
  monotonic_counter mc2seal;
  do {
    ret = sgx_create_pse_session();
  } while (ret == SGX_ERROR_BUSY && busy_retry_times--);
  if (ret != SGX_SUCCESS) {
    return ret; // todo: Clear mem
  }

  ret = read_and_verify_monotonic_counter((sgx_sealed_data_t*)sealed_mc_result,
    &mc_unsealed);

  *mc_value = mc_unsealed.mc_value;

  /* remember to clear secret data after been used by memset_s */
  memset_s(&mc_unsealed, sizeof(monotonic_counter), 0,
    sizeof(monotonic_counter));

  /* remember to clear secret data after been used by memset_s */
  memset_s(&mc2seal, sizeof(monotonic_counter), 0,
    sizeof(monotonic_counter));
  sgx_close_pse_session();
  return ret;
}
