#include "Decoder.h"

#include "Logger.h"

namespace armhook {

Decoder::Decoder()
	: mode_(MODE_ARM)
{}

bool Decoder::BytesToSave(void *op, bool arm, uint8_t required, uint8_t *total)
{
	void *iter = op;

	mode_ = arm ? MODE_ARM : MODE_THUMB;
	*total = 0;

	LOG_DEBUG("Detour size: %d, mode: %d", required, mode_);

	while (*total < required) {
		uint8_t size = 0;
		if (!ProcessInstruction(&iter, &size))
			return false;

		*total += size;
	}

	return true;
}

bool Decoder::ProcessInstruction(void **iter, uint8_t *size)
{
	Instruction inst;
	inst.arm= *((uint32_t*)(*iter));

	switch (mode_) {
	case MODE_ARM:
		*((uint8_t**)iter) += sizeof(inst.arm);
		*size = sizeof(inst.arm);

		LOG_DEBUG("instruction [%d]: %08x", *size, inst.arm);

		CheckInstruction(inst.arm);
		break;

	case MODE_THUMB:
		if ((((inst.thumb16 & 0xe000) >> 13) == 0x7) &&
			(((inst.thumb16 & 0x1800) >> 11) != 0x00)) {
			*((uint8_t**)iter) += sizeof(inst.thumb32);
			*size = sizeof(inst.thumb32);

			LOG_DEBUG("instruction [%d]: %04x %04x", *size,
				inst.thumb32.code1, inst.thumb32.code2);

			CheckInstruction(inst.thumb32);
		} else {
			*((uint8_t**)iter) += sizeof(inst.thumb16);
			*size = sizeof(inst.thumb16);

			LOG_DEBUG("instruction [%d]: %04x", *size,
				inst.thumb16);

			CheckInstruction(inst.thumb16);
		}
		break;
	}

	/*
	 * TODO: a couple of instructions might make some trouble, especially
	 * relative branches, or PC relative memory access, uncertain to what
	 * extend those instructions can be 'fixed'. This might be a problem why
	 * the target process might crash
	 */

	return true;
}

bool Decoder::CheckInstruction(const ArmCode &code)
{
	return true;
}

bool Decoder::CheckInstruction(const Thumb16Code &code)
{
	return true;
}

bool Decoder::CheckInstruction(const Thumb32Code &code)
{
	return true;
}

} /* namespace armhook */
