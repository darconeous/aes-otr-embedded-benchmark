idf_component_register(
    SRCS "main.c"
         "../../../src/otr128.c"
         "../../../src/aes128_soft.c"
         "../../../src/backend_esp32.c"
         "../../../src/bench.c"
    INCLUDE_DIRS "../../../include"
)
