#include "quicerror.h"

const char* quic_error_name(uint64_t code) {
    if (QUIC_IS_CRYPTO_ERROR(code))
        return "CRYPTO_ERROR";

    switch (code) {
    case QUIC_NO_ERROR:                  return "NO_ERROR";
    case QUIC_INTERNAL_ERROR:            return "INTERNAL_ERROR";
    case QUIC_CONNECTION_REFUSED:        return "CONNECTION_REFUSED";
    case QUIC_FLOW_CONTROL_ERROR:        return "FLOW_CONTROL_ERROR";
    case QUIC_STREAM_LIMIT_ERROR:        return "STREAM_LIMIT_ERROR";
    case QUIC_STREAM_STATE_ERROR:        return "STREAM_STATE_ERROR";
    case QUIC_FINAL_SIZE_ERROR:          return "FINAL_SIZE_ERROR";
    case QUIC_FRAME_ENCODING_ERROR:      return "FRAME_ENCODING_ERROR";
    case QUIC_TRANSPORT_PARAMETER_ERROR: return "TRANSPORT_PARAMETER_ERROR";
    case QUIC_CONNECTION_ID_LIMIT_ERROR: return "CONNECTION_ID_LIMIT_ERROR";
    case QUIC_PROTOCOL_VIOLATION:        return "PROTOCOL_VIOLATION";
    case QUIC_INVALID_TOKEN:             return "INVALID_TOKEN";
    case QUIC_APPLICATION_ERROR:         return "APPLICATION_ERROR";
    case QUIC_CRYPTO_BUFFER_EXCEEDED:    return "CRYPTO_BUFFER_EXCEEDED";
    case QUIC_KEY_UPDATE_ERROR:          return "KEY_UPDATE_ERROR";
    case QUIC_AEAD_LIMIT_REACHED:        return "AEAD_LIMIT_REACHED";
    case QUIC_NO_VIABLE_PATH:            return "NO_VIABLE_PATH";
    default:                             return "UNKNOWN";
    }
}
