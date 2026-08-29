import sys
from pathlib import Path
from types import SimpleNamespace


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from module.ghidra_pipe import decompile


class FakeAddress:
    def __init__(self, offset):
        self.offset = offset

    def getOffset(self):
        return self.offset

    def __str__(self):
        return f"0x{self.offset:x}"


class FakeInstruction:
    def __init__(self, address, mnemonic, operands=()):
        self.address = FakeAddress(address)
        self.mnemonic = mnemonic
        self.operands = operands
        self.previous = None
        self.next = None

    def getAddress(self):
        return self.address

    def getMnemonicString(self):
        return self.mnemonic

    def getNumOperands(self):
        return len(self.operands)

    def getDefaultOperandRepresentation(self, index):
        return self.operands[index]

    def getPrevious(self):
        return self.previous

    def getNext(self):
        return self.next


class FakeBody:
    def __init__(self, addresses):
        self.addresses = set(addresses)

    def contains(self, address):
        return address.getOffset() in self.addresses

    def getNumAddresses(self):
        return len(self.addresses)


class FakeReferenceType:
    def __init__(self, call=False, indirect=False, computed=False):
        self.call = call
        self.indirect = indirect
        self.computed = computed

    def isCall(self):
        return self.call

    def isIndirect(self):
        return self.indirect

    def isComputed(self):
        return self.computed


class FakeReference:
    def __init__(self, source, target, reference_type, external=None):
        self.source = FakeAddress(source)
        self.target = FakeAddress(target) if target is not None else None
        self.reference_type = reference_type
        self.external = external

    def getFromAddress(self):
        return self.source

    def getToAddress(self):
        return self.target

    def getReferenceType(self):
        return self.reference_type

    def isExternalReference(self):
        return self.external is not None

    def getExternalLocation(self):
        return self.external


class FakeData:
    def __init__(self, address, value):
        self.address = FakeAddress(address)
        self.value = value

    def getAddress(self):
        return self.address

    def hasStringValue(self):
        return True

    def getValue(self):
        return self.value


class FakeListing:
    def __init__(self, instructions, data):
        self.instructions = {item.address.offset: item for item in instructions}
        self.data = {item.address.offset: item for item in data}

    def getInstructionAt(self, address):
        return self.instructions.get(address.getOffset())

    def getInstructionContaining(self, address):
        return self.getInstructionAt(address)

    def getDataContaining(self, address):
        return self.data.get(address.getOffset()) if address is not None else None


class FakeReferenceManager:
    def __init__(self, sources, references):
        self.sources = sources
        self.references = references

    def getReferenceSourceIterator(self, body, forward):
        return iter(self.sources)

    def getReferencesFrom(self, address):
        return self.references.get(address.getOffset(), [])


class FakeFunction:
    def __init__(self, name="FUN_1000", entry=0x1000, body=None):
        self.name = name
        self.entry = FakeAddress(entry)
        self.body = body or FakeBody(range(0x1000, 0x1008))

    def getName(self):
        return self.name

    def getEntryPoint(self):
        return self.entry

    def getBody(self):
        return self.body


class FakeFunctionManager:
    def __init__(self, targets=None):
        self.targets = targets or {}

    def getFunctionAt(self, address):
        return self.targets.get(address.getOffset()) if address is not None else None


class FakeProgram:
    def __init__(self, listing, reference_manager, function_manager):
        self.listing = listing
        self.reference_manager = reference_manager
        self.function_manager = function_manager

    def getListing(self):
        return self.listing

    def getReferenceManager(self):
        return self.reference_manager

    def getFunctionManager(self):
        return self.function_manager


class FakeDecompiler:
    def __init__(self, result, last_message=""):
        self.result = result
        self.last_message = last_message
        self.calls = 0

    def decompileFunction(self, func, timeout, monitor):
        self.calls += 1
        return self.result

    def getLastMessage(self):
        return self.last_message


class FakeResults:
    def __init__(self, completed=False, timed_out=False, code=None, error_message=""):
        self.completed = completed
        self.timed_out = timed_out
        self.code = code
        self.error_message = error_message

    def decompileCompleted(self):
        return self.completed

    def isTimedOut(self):
        return self.timed_out

    def getErrorMessage(self):
        return self.error_message

    def getDecompiledFunction(self):
        if self.code is None:
            return None
        return SimpleNamespace(getC=lambda: self.code)


def _program_with_evidence():
    instructions = [
        FakeInstruction(0x1000, "mov", ("rax", "rcx")),
        FakeInstruction(0x1001, "lea", ("rdx", "[rip + string]")),
        FakeInstruction(0x1002, "call", ("qword ptr [rip + api]",)),
        FakeInstruction(0x1003, "ret"),
    ]
    for previous, current in zip(instructions, instructions[1:]):
        previous.next = current
        current.previous = previous

    source = FakeAddress(0x1002)
    string_reference = FakeReference(0x1002, 0x2000, FakeReferenceType())
    external = SimpleNamespace(getLibraryName=lambda: "KERNEL32.dll", getLabel=lambda: "CreateMutexW")
    external_reference = FakeReference(
        0x1002,
        0x3000,
        FakeReferenceType(call=True, indirect=True),
        external=external,
    )
    unresolved_reference = FakeReference(
        0x1002,
        None,
        FakeReferenceType(call=True, indirect=True),
    )
    references = {
        0x1002: [string_reference, string_reference, external_reference, unresolved_reference]
    }
    listing = FakeListing(instructions, [FakeData(0x2000, "http://149.248.77.59/favicon.ico/")])
    ref_manager = FakeReferenceManager([source, source], references)
    program = FakeProgram(listing, ref_manager, FakeFunctionManager())
    return program, FakeFunction(body=FakeBody(range(0x1000, 0x1004)))


def test_completed_decompilation_returns_c_code():
    func = FakeFunction()
    decompiler_instance = FakeDecompiler(FakeResults(completed=True, code="void f() {}"))

    result = decompile._decompile_one(object(), decompiler_instance, func, object())

    assert result == "void f() {}"
    assert decompiler_instance.calls == 1


def test_only_timeout_uses_string_and_assembly_fallback():
    program, func = _program_with_evidence()
    decompiler_instance = FakeDecompiler(FakeResults(timed_out=True))

    result = decompile._decompile_one(program, decompiler_instance, func, object())

    assert "[GHIDRA FALLBACK: decompilation timed out]" in result
    assert "http://149.248.77.59/favicon.ico/" in result
    assert "KERNEL32.dll!CreateMutexW" in result
    assert "indirect/unresolved (?)" not in result
    assert "FUNCTION: FUN_" not in result
    assert result.count("evidence @ 0x1002") == 1
    assert result.index("STRING") < result.index("FUNCTION:") < result.index("assembly:")
    assert result.count("0x2000") == 1
    assert decompiler_instance.calls == 1


def test_cancellation_does_not_use_timeout_fallback():
    program, func = _program_with_evidence()
    decompiler_instance = FakeDecompiler(FakeResults())

    result = decompile._decompile_one(program, decompiler_instance, func, object())

    assert result is None


def test_null_result_uses_fallback_only_for_timeout_diagnostic():
    program, func = _program_with_evidence()
    decompiler_instance = FakeDecompiler(None, last_message="Decompiler timeout")

    result = decompile._decompile_one(program, decompiler_instance, func, object())

    assert result.startswith("[GHIDRA FALLBACK: decompilation timed out]")


def test_null_result_without_timeout_diagnostic_is_failure():
    program, func = _program_with_evidence()
    decompiler_instance = FakeDecompiler(None, last_message="Decompiler crashed")

    result = decompile._decompile_one(program, decompiler_instance, func, object())

    assert result is None


def test_result_error_message_can_identify_timeout_without_is_timed_out():
    program, func = _program_with_evidence()
    decompiler_instance = FakeDecompiler(
        FakeResults(error_message="decompiler timed out"),
        last_message="",
    )
    decompiler_instance.result.isTimedOut = None

    result = decompile._decompile_one(program, decompiler_instance, func, object())

    assert result.startswith("[GHIDRA FALLBACK: decompilation timed out]")


def test_repeated_string_reference_is_rendered_once_but_keeps_ordered_events():
    program, func = _program_with_evidence()
    data_reference = FakeReference(0x1001, 0x2000, FakeReferenceType())
    program.reference_manager.references[0x1001] = [data_reference]
    program.reference_manager.sources.insert(0, FakeAddress(0x1001))
    decompiler_instance = FakeDecompiler(FakeResults(timed_out=True))

    result = decompile._decompile_one(program, decompiler_instance, func, object())

    assert result.count("evidence @ ") == 2
    assert result.count("STRING 0x2000") == 1


def test_anonymous_function_target_does_not_create_evidence_event():
    program, func = _program_with_evidence()
    anonymous = FakeFunction(name="FUN_1400032d1", entry=0x3000)
    program.function_manager.targets[0x3000] = anonymous
    program.reference_manager.references[0x1002].append(
        FakeReference(0x1002, 0x3000, FakeReferenceType(call=True))
    )
    decompiler_instance = FakeDecompiler(FakeResults(timed_out=True))

    result = decompile._decompile_one(program, decompiler_instance, func, object())

    assert "FUNCTION: FUN_1400032d1" not in result
    assert "FUNCTION: KERNEL32.dll!CreateMutexW" in result
