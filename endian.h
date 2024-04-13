#ifndef ENDIAN_H
#define ENDIAN_H

// Endianness conversion macros intended for use with constant expressions

#define hton16c(x) (((uint16_t)(x)<<8) | ((uint16_t)(x)>>8))
#define hton32c(x) (((uint32_t)(x)<<24) | (((uint32_t)(x)&0x0000ff00)<<8) | \
        (((uint32_t)(x)&0x00ff0000)>>8) | ((uint32_t)(x)>>24))

/* TODO assembly versions */
#define hton16(x) hton16c(x)
#define hton32(x) hton32c(x)

#define ntoh16(x) hton16c(x)
#define ntoh32(x) hton32c(x)

#endif
