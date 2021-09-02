from typing import Optional


class HeapError(Exception):
    pass


class HeapBlock:
    next: Optional['HeapBlock']

    def __init__(self):
        self.address = 0
        self.size = 0
        self.free = False
        self.next = None


class HeapAllocator:

    def __init__(self, start: int, end: int):
        """
        :param int start: Start address of the heap.
        :param int end: End address of the heap.
        """
        self._start = start
        self._pos = start
        self._end = end
        self._head = None

    def allocate(self, size: int) -> int:
        """
        :param int size: The amount of bytes to allocate.
        """
        if size <= 0:
            return 0

        block = None

        if self._head is None:
            block = self._create_block(size)
            self._head = block
        else:
            block, last = self._find_free_block(size)

            if not block:
                block = self._create_block(size, last)
            else:
                block.free = False

        return block.address

    def free(self, address: int):
        if address == 0:
            return

        block = self._find_block(address)

        if block is None:
            raise HeapError('Attempted to free non existing block at 0x%x' % address)

        block.free = True

    def _create_block(self, size: int, last: HeapBlock = None) -> HeapBlock:
        """
        Create a block and add it to the end of the heap list.
        """
        # Create new block.
        block = HeapBlock()
        block.address = self._increment_data(size)
        block.size = size
        block.free = False
        block.next = None

        # Append to last block.
        if last is not None:
            last.next = block

        return block

    def _find_block(self, address: int):
        """
        Finds the block that was assigned to the given address.
        """
        block = self._head

        while block is not None and block.address != address:
            block = block.next

        return block

    def _find_free_block(self, size: int) -> (Optional[HeapBlock], Optional[HeapBlock]):
        """
        Attempts to find a free block that can contain the requested size.
        """
        last = None
        block = self._head

        while block is not None and not (block.free and block.size >= size):
            last = block
            block = block.next

        return block, last

    def _increment_data(self, size: int):
        """
        Increments the current pointer, which simulates the sbrk call.
        https://linux.die.net/man/2/sbrk
        """
        res = self._pos
        self._pos += size
        return res
