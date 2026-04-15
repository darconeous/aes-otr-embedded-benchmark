#include "stm32u5xx_hal.h"
#include "stm32u5xx_hal_cryp.h"

void HAL_MspInit(void) {
    __HAL_RCC_PWR_CLK_ENABLE();
}

void HAL_CRYP_MspInit(CRYP_HandleTypeDef *hcryp) {
    if (hcryp->Instance == AES) {
        __HAL_RCC_AES_CLK_ENABLE();
    }
}

void HAL_CRYP_MspDeInit(CRYP_HandleTypeDef *hcryp) {
    if (hcryp->Instance == AES) {
        __HAL_RCC_AES_CLK_DISABLE();
    }
}

void Error_Handler(void) {
    __disable_irq();
    for (;;) {
    }
}
