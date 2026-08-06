#include "h3error.h"

const char* h3_error_name(uint64_t code) {
    switch (code) {
    case H3_NO_ERROR:                return "H3_NO_ERROR";
    case H3_GENERAL_PROTOCOL_ERROR:  return "H3_GENERAL_PROTOCOL_ERROR";
    case H3_INTERNAL_ERROR:          return "H3_INTERNAL_ERROR";
    case H3_STREAM_CREATION_ERROR:   return "H3_STREAM_CREATION_ERROR";
    case H3_CLOSED_CRITICAL_STREAM:  return "H3_CLOSED_CRITICAL_STREAM";
    case H3_FRAME_UNEXPECTED:        return "H3_FRAME_UNEXPECTED";
    case H3_FRAME_ERROR:             return "H3_FRAME_ERROR";
    case H3_EXCESSIVE_LOAD:          return "H3_EXCESSIVE_LOAD";
    case H3_ID_ERROR:                return "H3_ID_ERROR";
    case H3_SETTINGS_ERROR:          return "H3_SETTINGS_ERROR";
    case H3_MISSING_SETTINGS:        return "H3_MISSING_SETTINGS";
    case H3_REQUEST_REJECTED:        return "H3_REQUEST_REJECTED";
    case H3_REQUEST_CANCELLED:       return "H3_REQUEST_CANCELLED";
    case H3_REQUEST_INCOMPLETE:      return "H3_REQUEST_INCOMPLETE";
    case H3_MESSAGE_ERROR:           return "H3_MESSAGE_ERROR";
    case H3_CONNECT_ERROR:           return "H3_CONNECT_ERROR";
    case H3_VERSION_FALLBACK:        return "H3_VERSION_FALLBACK";
    case QPACK_DECOMPRESSION_FAILED: return "QPACK_DECOMPRESSION_FAILED";
    case QPACK_ENCODER_STREAM_ERROR: return "QPACK_ENCODER_STREAM_ERROR";
    case QPACK_DECODER_STREAM_ERROR: return "QPACK_DECODER_STREAM_ERROR";
    default:                         return "UNKNOWN";
    }
}
