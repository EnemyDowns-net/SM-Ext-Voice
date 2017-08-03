#ifndef RINGBUFFER_H
#define RINGBUFFER_H

#include <stdint.h>
#include <stdlib.h>

class CRingBuffer
{
public:
	const size_t m_BufferSize;
	CRingBuffer();

	bool Pop(int16_t *pData, size_t Samples);
	bool Push(int16_t *pData, size_t BufLen);

	size_t TotalLength();
	size_t TotalFree();
	size_t CurrentLength();
	size_t CurrentFree();

	size_t GetReadIndex();
	size_t GetWriteIndex();
	void SetWriteIndex(size_t WriteIndex);

public:
	void Mix(int16_t *pData, size_t Samples);

	size_t m_ReadIndex;
	size_t m_WriteIndex;
	size_t m_Length;

	int16_t m_aBuffer[32768];
};

#endif // RINGBUFFER_H
