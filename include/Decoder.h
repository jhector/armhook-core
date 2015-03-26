#ifndef ARMHOOK_DECODER_H_
#define ARMHOOK_DECODER_H_

#include <stdint.h>

namespace armhook {

class Decoder
{
public:
	typedef enum {
		MODE_ARM,
		MODE_THUMB
	} Mode;

	typedef uint32_t ArmCode;
	typedef uint16_t Thumb16Code;

	typedef struct __attribute__((packed)) {
		uint16_t code1;
		uint16_t code2;
	} Thumb32Code;


	typedef union {
		Thumb16Code thumb16;
		Thumb32Code thumb32;
		ArmCode arm;
	} Instruction;

	Decoder();

	bool BytesToSave(void *op, bool arm, uint8_t required, uint8_t *total);

private:
	bool ProcessInstruction(void **iter, uint8_t *size);

	bool CheckInstruction(const ArmCode &code);
	bool CheckInstruction(const Thumb16Code &code);
	bool CheckInstruction(const Thumb32Code &code);

	Mode mode_; /* instruction mode, 0 = arm, 1 = thumb */
};

} /* namespace armhook */

#endif /* ARMHOOK_DECODER_H_ */
