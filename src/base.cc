
#include <SDK/sdhd_sdk.hh>
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <atomic>

using namespace UFG;
HMODULE gEternalLightbarModule = nullptr;
// Last vehicle owner observed while Wei was inside.
// Diagnostic only: this does NOT keep the game object alive.
uintptr_t gLastVehicleOwner = 0;
// Eternal Lightbar experimental prototype.
// Keep disabled until the write conditions are verified.
constexpr bool kEnableLightbarPrototype = true;
// Experimental cleanup request.
// Must only be acted upon after revalidating the target vehicle.
constexpr bool kRequestPrototypeCleanup = false;


// Prototype restoration tracking.
// These values are not yet used to modify game memory.
uintptr_t gPrototypeVehicleOwner = 0;
uintptr_t gPrototypeCopUnit = 0;
uint8_t gPrototypeOriginalFlags = 0;
bool gPrototypeFlagModified = false;
// Read-only helper for checking pointer-sized fields.
bool TryReadPointer(uintptr_t address, uintptr_t& result)
{
    result = 0;

    if (address == 0 ||
        address > UINTPTR_MAX - (sizeof(uintptr_t) - 1))
        return false;

    MEMORY_BASIC_INFORMATION mbi{};

    if (VirtualQuery(
        reinterpret_cast<LPCVOID>(address),
        &mbi, sizeof(mbi)) == 0 ||
        mbi.State != MEM_COMMIT ||
        (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
        !(mbi.Protect & (
            PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
            PAGE_EXECUTE_WRITECOPY)))
        return false;

    const uintptr_t regionStart =
        reinterpret_cast<uintptr_t>(mbi.BaseAddress);

    if (address < regionStart ||
        address - regionStart >= mbi.RegionSize ||
        mbi.RegionSize - (address - regionStart) <
        sizeof(uintptr_t))
        return false;

    result = *reinterpret_cast<const uintptr_t*>(address);
    return true;
}

// Restore only the scripted-light bit added by our prototype.
// Call only after independently validating the same live CopUnit.
bool RestorePrototypeFlag(uintptr_t verifiedCopUnit)
{
    if (!gPrototypeFlagModified ||
        verifiedCopUnit == 0 ||
        verifiedCopUnit != gPrototypeCopUnit ||
        verifiedCopUnit > UINTPTR_MAX - 0x1E1)
        return false;

    const uintptr_t flagAddress = verifiedCopUnit + 0x1E1;

    MEMORY_BASIC_INFORMATION mbi{};

    if (VirtualQuery(
        reinterpret_cast<LPCVOID>(flagAddress),
        &mbi, sizeof(mbi)) == 0 ||
        mbi.State != MEM_COMMIT ||
        (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
        !(mbi.Protect & (
            PAGE_READWRITE | PAGE_EXECUTE_READWRITE)))
        return false;

    const uintptr_t regionStart =
        reinterpret_cast<uintptr_t>(mbi.BaseAddress);

    if (flagAddress < regionStart ||
        flagAddress - regionStart >= mbi.RegionSize)
        return false;

    auto* flags = reinterpret_cast<uint8_t*>(flagAddress);

    // Preserve every other bit.
    *flags = static_cast<uint8_t>(*flags & ~0x04u);

    gPrototypeFlagModified = false;
    gPrototypeVehicleOwner = 0;
    gPrototypeCopUnit = 0;

    OutputDebugStringA(
        "[EternalLightbar] PROTOTYPE: scripted-light bit restored\n");

    return true;
}

void ValidatePlayerPointer();

namespace InGameOnUpdate
{
    SDK::Hook gHook;

    std::atomic<unsigned int> vehicleDiagnosticCounter{ 0 };

    void __fastcall Fn(GameState* game_state, f32 deltaTime)
    {
        // Forward execution to the original game function.
        gHook(game_state, deltaTime);

        const unsigned int diagnosticCount =
            vehicleDiagnosticCounter.fetch_add(
                1, std::memory_order_relaxed
            ) + 1;

        if (diagnosticCount == 1 || diagnosticCount % 30 == 0)
        {
            ValidatePlayerPointer();
        }
    }
}

// Read-only diagnostic: does the running executable
// contain the GameStateInGame OnUpdate pointer
// that we identified in Ghidra?
void ValidateGameStatePointer()
{
    const auto base = reinterpret_cast<uintptr_t>(
        GetModuleHandleW(nullptr)
        );

    constexpr uintptr_t slotRva = 0x1784BF8;
    constexpr uintptr_t expectedFunctionRva = 0x412490;

    const uintptr_t slotAddress = base + slotRva;
    const uintptr_t expectedAddress = base + expectedFunctionRva;

    MEMORY_BASIC_INFORMATION mbi{};

    if (VirtualQuery(
        reinterpret_cast<LPCVOID>(slotAddress),
        &mbi,
        sizeof(mbi)) == 0 ||
        mbi.State != MEM_COMMIT ||
        (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
    {
        OutputDebugStringA(
            "[EternalLightbar] GameState slot is not readable\n"
        );
        return;
    }

    // Verify the full eight-byte pointer lies within
    // the memory region reported by VirtualQuery.
    const uintptr_t regionStart =
        reinterpret_cast<uintptr_t>(mbi.BaseAddress);

    const uintptr_t regionEnd =
        regionStart + mbi.RegionSize;

    if (slotAddress < regionStart ||
        slotAddress >= regionEnd ||
        regionEnd - slotAddress < sizeof(uintptr_t))
    {
        OutputDebugStringA(
            "[EternalLightbar] GameState pointer crosses memory boundary\n"
        );
        return;
    }

    const uintptr_t actualAddress =
        *reinterpret_cast<const uintptr_t*>(slotAddress);

    char message[256]{};

    sprintf_s(
        message,
        "[EternalLightbar] OnUpdate slot RVA: 0x%llX; "
        "Actual function RVA: 0x%llX; "
        "Expected function RVA: 0x%llX; "
        "Match: %s\n",
        static_cast<unsigned long long>(slotRva),
        static_cast<unsigned long long>(actualAddress - base),
        static_cast<unsigned long long>(expectedFunctionRva),
        actualAddress == expectedAddress ? "YES" : "NO"
    );

    OutputDebugStringA(message);
}

void ValidatePlayerPointer()
{
    const uintptr_t base =
        reinterpret_cast<uintptr_t>(
            GetModuleHandleW(nullptr)
            );

    if (base == 0)
        return;

    constexpr uintptr_t playerSlotRva = 0x235C488;
    const uintptr_t slotAddress = base + playerSlotRva;

    MEMORY_BASIC_INFORMATION mbi{};

    if (VirtualQuery(
        reinterpret_cast<LPCVOID>(slotAddress),
        &mbi,
        sizeof(mbi)) == 0 ||
        mbi.State != MEM_COMMIT ||
        (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
    {
        OutputDebugStringA(
            "[EternalLightbar] Player slot not readable\n"
        );
        return;
    }

    const uintptr_t regionStart =
        reinterpret_cast<uintptr_t>(mbi.BaseAddress);

    if (slotAddress < regionStart ||
        slotAddress - regionStart >= mbi.RegionSize ||
        mbi.RegionSize - (slotAddress - regionStart)
        < sizeof(uintptr_t))
    {
        OutputDebugStringA(
            "[EternalLightbar] Player slot crosses memory boundary\n"
        );
        return;
    }

    const uintptr_t playerOwner =
        *reinterpret_cast<const uintptr_t*>(slotAddress);

    char message[256]{};

    sprintf_s(
        message,
        "[EternalLightbar] Player owner pointer: 0x%llX\n",
        static_cast<unsigned long long>(playerOwner)
    );

    OutputDebugStringA(message);

    if (playerOwner == 0 ||
    playerOwner > UINTPTR_MAX - 0x68)
{
    OutputDebugStringA(
        "[EternalLightbar] Invalid player owner address\n"
    );
    return;
}

const uintptr_t componentSlot = playerOwner + 0x68;

MEMORY_BASIC_INFORMATION componentMbi{};

if (VirtualQuery(
    reinterpret_cast<LPCVOID>(componentSlot),
    &componentMbi,
    sizeof(componentMbi)) == 0 ||
    componentMbi.State != MEM_COMMIT ||
    (componentMbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
    !(componentMbi.Protect & (
        PAGE_READONLY | PAGE_READWRITE |
        PAGE_WRITECOPY | PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
{
    OutputDebugStringA(
        "[EternalLightbar] Component slot not readable\n"
    );
    return;
}

const uintptr_t componentRegionStart =
reinterpret_cast<uintptr_t>(componentMbi.BaseAddress);

if (componentSlot < componentRegionStart ||
    componentSlot - componentRegionStart >= componentMbi.RegionSize ||
    componentMbi.RegionSize - (componentSlot - componentRegionStart)
    < sizeof(uintptr_t))
{
    OutputDebugStringA(
        "[EternalLightbar] Component slot crosses memory boundary\n"
    );
    return;
}

const uintptr_t componentTable =
    *reinterpret_cast<const uintptr_t*>(componentSlot);

char componentMessage[256]{};

sprintf_s(
    componentMessage,
    "[EternalLightbar] Wei component table: 0x%llX\n",
    static_cast<unsigned long long>(componentTable)
);

OutputDebugStringA(componentMessage);
// Read-only lookup: CharacterOccupantComponent slot (+0x2C0).
if (componentTable == 0 ||
    componentTable > UINTPTR_MAX - 0x2C0)
{
    OutputDebugStringA(
        "[EternalLightbar] Invalid component table pointer\n"
    );
    return;
}

const uintptr_t occupantSlot = componentTable + 0x2C0;

MEMORY_BASIC_INFORMATION occupantMbi{};

if (VirtualQuery(
    reinterpret_cast<LPCVOID>(occupantSlot),
    &occupantMbi,
    sizeof(occupantMbi)) == 0 ||
    occupantMbi.State != MEM_COMMIT ||
    (occupantMbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
    !(occupantMbi.Protect & (
        PAGE_READONLY | PAGE_READWRITE |
        PAGE_WRITECOPY | PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
{
    OutputDebugStringA(
        "[EternalLightbar] Occupant slot not readable\n"
    );
    return;
}

const uintptr_t occupantRegionStart =
reinterpret_cast<uintptr_t>(occupantMbi.BaseAddress);

if (occupantSlot < occupantRegionStart ||
    occupantSlot - occupantRegionStart >= occupantMbi.RegionSize ||
    occupantMbi.RegionSize -
    (occupantSlot - occupantRegionStart) < sizeof(uintptr_t))
{
    OutputDebugStringA(
        "[EternalLightbar] Occupant slot crosses memory boundary\n"
    );
    return;
}

const uintptr_t occupantComponent =
*reinterpret_cast<const uintptr_t*>(occupantSlot);

char occupantMessage[256]{};

sprintf_s(
    occupantMessage,
    "[EternalLightbar] CharacterOccupantComponent: 0x%llX\n",
    static_cast<unsigned long long>(occupantComponent)
);

OutputDebugStringA(occupantMessage);

// Read-only lookup: occupant component +0x70.
if (occupantComponent == 0 ||
    occupantComponent > UINTPTR_MAX - 0x70)
{
    if (occupantComponent == 0 && gLastVehicleOwner != 0)
    {
        char exitMessage[256]{};

        sprintf_s(
            exitMessage,
            "[EternalLightbar] Wei outside vehicle; "
            "last verified owner: 0x%llX\n",
            static_cast<unsigned long long>(gLastVehicleOwner)
        );

        OutputDebugStringA(exitMessage);

        // Recheck the cached vehicle's component chain.
// Read-only; matching pointers do not guarantee object lifetime.

        const uintptr_t cachedOwner = gLastVehicleOwner;

        uintptr_t cachedTable = 0;
        uintptr_t cachedCopUnit = 0;
        uintptr_t cachedBacklink = 0;

        bool chainValid = false;

        if (cachedOwner <= UINTPTR_MAX - 0x68 &&
            TryReadPointer(cachedOwner + 0x68, cachedTable) &&
            cachedTable != 0 &&
            cachedTable <= UINTPTR_MAX - 0x110 &&
            TryReadPointer(cachedTable + 0x110, cachedCopUnit) &&
            cachedCopUnit != 0 &&
            cachedCopUnit <= UINTPTR_MAX - 0x28 &&
            TryReadPointer(cachedCopUnit + 0x28, cachedBacklink))
        {
            chainValid = (cachedBacklink == cachedOwner);
        }
        // Check whether this is our modified prototype vehicle.
// Read-only: do not restore the flag here.
        const bool prototypeVehicleMatches =
            chainValid &&
            gPrototypeFlagModified &&
            cachedOwner == gPrototypeVehicleOwner &&
            cachedCopUnit == gPrototypeCopUnit;

        if (gPrototypeFlagModified)
        {
            OutputDebugStringA(
                prototypeVehicleMatches
                ? "[EternalLightbar] PROTOTYPE: post-exit vehicle MATCH\n"
                : "[EternalLightbar] PROTOTYPE: post-exit vehicle MISMATCH\n"
            );
        }

        // === Experimental manual cleanup ===
// Only attempt restoration for the matching tracked vehicle.
        if (kRequestPrototypeCleanup &&
            prototypeVehicleMatches)
        {
            RestorePrototypeFlag(cachedCopUnit);
        }


        OutputDebugStringA(
            chainValid
            ? "[EternalLightbar] Post-exit CopUnit backlink: MATCH\n"
            : "[EternalLightbar] Post-exit CopUnit backlink: INVALID\n"
        );

        // === Post-exit VehicleEffects diagnostic ===
 // Only inspect the effects component when the backlink matches.

        if (chainValid && cachedCopUnit <= UINTPTR_MAX - 0xD0)
        {
            uintptr_t cachedEffects = 0;

            if (TryReadPointer(cachedCopUnit + 0xD0, cachedEffects) &&
                cachedEffects != 0 &&
                cachedEffects <= UINTPTR_MAX - 0x160)
            {
                const uintptr_t stateAddress = cachedEffects + 0x160;

                MEMORY_BASIC_INFORMATION stateMbi{};

                if (VirtualQuery(
                    reinterpret_cast<LPCVOID>(stateAddress),
                    &stateMbi,
                    sizeof(stateMbi)) != 0 &&
                    stateMbi.State == MEM_COMMIT &&
                    !(stateMbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
                    (stateMbi.Protect & (
                        PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                        PAGE_EXECUTE_WRITECOPY)))
                {
                    const uintptr_t regionStart =
                        reinterpret_cast<uintptr_t>(stateMbi.BaseAddress);

                    if (stateAddress >= regionStart &&
                        stateAddress - regionStart < stateMbi.RegionSize &&
                        stateMbi.RegionSize -
                        (stateAddress - regionStart) >= sizeof(uint32_t))
                    {
                        const uint32_t state =
                            *reinterpret_cast<const uint32_t*>(stateAddress);

                        char message[256]{};

                        sprintf_s(
                            message,
                            "[EternalLightbar] Post-exit VehicleEffects state: %u\n",
                            static_cast<unsigned int>(state)
                        );

                        OutputDebugStringA(message);
                    }
                }
            }
        }
    }

    return;
}

const uintptr_t vehicleRefSlot = occupantComponent + 0x70;

MEMORY_BASIC_INFORMATION vehicleRefMbi{};

if (VirtualQuery(
    reinterpret_cast<LPCVOID>(vehicleRefSlot),
    &vehicleRefMbi,
    sizeof(vehicleRefMbi)) == 0 ||
    vehicleRefMbi.State != MEM_COMMIT ||
    (vehicleRefMbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
    !(vehicleRefMbi.Protect & (
        PAGE_READONLY | PAGE_READWRITE |
        PAGE_WRITECOPY | PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
{
    OutputDebugStringA(
        "[EternalLightbar] Vehicle reference slot not readable\n"
    );
    return;
}

const uintptr_t vehicleRefRegionStart =
reinterpret_cast<uintptr_t>(vehicleRefMbi.BaseAddress);

if (vehicleRefSlot < vehicleRefRegionStart ||
    vehicleRefSlot - vehicleRefRegionStart >= vehicleRefMbi.RegionSize ||
    vehicleRefMbi.RegionSize -
    (vehicleRefSlot - vehicleRefRegionStart) < sizeof(uintptr_t))
{
    OutputDebugStringA(
        "[EternalLightbar] Vehicle reference slot crosses memory boundary\n"
    );
    return;
}

const uintptr_t vehicleOccupantRef =
*reinterpret_cast<const uintptr_t*>(vehicleRefSlot);

char vehicleRefMessage[256]{};

sprintf_s(
    vehicleRefMessage,
    "[EternalLightbar] Vehicle occupant reference: 0x%llX\n",
    static_cast<unsigned long long>(vehicleOccupantRef)
);

OutputDebugStringA(vehicleRefMessage);
// Read-only lookup: vehicle reference +0x28.
if (vehicleOccupantRef == 0 ||
    vehicleOccupantRef > UINTPTR_MAX - 0x28)
{
    return;
}

const uintptr_t vehicleOwnerSlot = vehicleOccupantRef + 0x28;

MEMORY_BASIC_INFORMATION vehicleOwnerMbi{};

if (VirtualQuery(
    reinterpret_cast<LPCVOID>(vehicleOwnerSlot),
    &vehicleOwnerMbi,
    sizeof(vehicleOwnerMbi)) == 0 ||
    vehicleOwnerMbi.State != MEM_COMMIT ||
    (vehicleOwnerMbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
    !(vehicleOwnerMbi.Protect & (
        PAGE_READONLY | PAGE_READWRITE |
        PAGE_WRITECOPY | PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
{
    OutputDebugStringA(
        "[EternalLightbar] Vehicle owner slot not readable\n"
    );
    return;
}

const uintptr_t vehicleOwnerRegionStart =
reinterpret_cast<uintptr_t>(vehicleOwnerMbi.BaseAddress);

if (vehicleOwnerSlot < vehicleOwnerRegionStart ||
    vehicleOwnerSlot - vehicleOwnerRegionStart >= vehicleOwnerMbi.RegionSize ||
    vehicleOwnerMbi.RegionSize -
    (vehicleOwnerSlot - vehicleOwnerRegionStart) < sizeof(uintptr_t))
{
    OutputDebugStringA(
        "[EternalLightbar] Vehicle owner slot crosses memory boundary\n"
    );
    return;
}

const uintptr_t vehicleOwner =
*reinterpret_cast<const uintptr_t*>(vehicleOwnerSlot);

char vehicleOwnerMessage[256]{};

sprintf_s(
    vehicleOwnerMessage,
    "[EternalLightbar] Vehicle owner pointer: 0x%llX\n",
    static_cast<unsigned long long>(vehicleOwner)
);

OutputDebugStringA(vehicleOwnerMessage);
// === Vehicle component table: vehicleOwner +0x68 ===

if (vehicleOwner == 0 || vehicleOwner > UINTPTR_MAX - 0x68)
{
    OutputDebugStringA(
        "[EternalLightbar] Invalid vehicle owner pointer\n");
    return;
}

const uintptr_t vehicleTableSlot = vehicleOwner + 0x68;
MEMORY_BASIC_INFORMATION vehicleTableMbi{};

if (VirtualQuery(
    reinterpret_cast<LPCVOID>(vehicleTableSlot),
    &vehicleTableMbi,
    sizeof(vehicleTableMbi)) == 0 ||
    vehicleTableMbi.State != MEM_COMMIT ||
    (vehicleTableMbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
    !(vehicleTableMbi.Protect & (
        PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
        PAGE_EXECUTE_WRITECOPY)))
{
    OutputDebugStringA(
        "[EternalLightbar] Vehicle component table slot unreadable\n");
    return;
}

const uintptr_t vehicleTableRegion =
reinterpret_cast<uintptr_t>(vehicleTableMbi.BaseAddress);

if (vehicleTableSlot < vehicleTableRegion ||
    vehicleTableSlot - vehicleTableRegion >= vehicleTableMbi.RegionSize ||
    vehicleTableMbi.RegionSize -
    (vehicleTableSlot - vehicleTableRegion) < sizeof(uintptr_t))
{
    OutputDebugStringA(
        "[EternalLightbar] Vehicle table slot crosses memory boundary\n");
    return;
}

const uintptr_t vehicleComponentTable =
*reinterpret_cast<const uintptr_t*>(vehicleTableSlot);

char vehicleTableMessage[256]{};
sprintf_s(
    vehicleTableMessage,
    "[EternalLightbar] Vehicle component table: 0x%llX\n",
    static_cast<unsigned long long>(vehicleComponentTable));
OutputDebugStringA(vehicleTableMessage);


// === CopUnit component: vehicleComponentTable +0x110 ===

if (vehicleComponentTable == 0 ||
    vehicleComponentTable > UINTPTR_MAX - 0x110)
{
    OutputDebugStringA(
        "[EternalLightbar] Invalid vehicle component table\n");
    return;
}

const uintptr_t copUnitSlot = vehicleComponentTable + 0x110;
MEMORY_BASIC_INFORMATION copUnitMbi{};

if (VirtualQuery(
    reinterpret_cast<LPCVOID>(copUnitSlot),
    &copUnitMbi,
    sizeof(copUnitMbi)) == 0 ||
    copUnitMbi.State != MEM_COMMIT ||
    (copUnitMbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
    !(copUnitMbi.Protect & (
        PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
        PAGE_EXECUTE_WRITECOPY)))
{
    OutputDebugStringA(
        "[EternalLightbar] CopUnit slot unreadable\n");
    return;
}

const uintptr_t copUnitRegion =
reinterpret_cast<uintptr_t>(copUnitMbi.BaseAddress);

if (copUnitSlot < copUnitRegion ||
    copUnitSlot - copUnitRegion >= copUnitMbi.RegionSize ||
    copUnitMbi.RegionSize -
    (copUnitSlot - copUnitRegion) < sizeof(uintptr_t))
{
    OutputDebugStringA(
        "[EternalLightbar] CopUnit slot crosses memory boundary\n");
    return;
}

const uintptr_t copUnit =
*reinterpret_cast<const uintptr_t*>(copUnitSlot);

char copUnitMessage[256]{};
sprintf_s(
    copUnitMessage,
    "[EternalLightbar] CopUnit candidate: 0x%llX\n",
    static_cast<unsigned long long>(copUnit));
OutputDebugStringA(copUnitMessage);

// === Read-only CopUnit identity and lighting diagnostics ===

if (copUnit == 0 || copUnit > UINTPTR_MAX - 0x1E1)
{
    OutputDebugStringA(
        "[EternalLightbar] Invalid CopUnit candidate\n");
    return;
}

const uintptr_t copStart = copUnit + 0x28;
const uintptr_t copEnd = copUnit + 0x1E1;

MEMORY_BASIC_INFORMATION copMbi{};

if (VirtualQuery(
    reinterpret_cast<LPCVOID>(copStart),
    &copMbi,
    sizeof(copMbi)) == 0 ||
    copMbi.State != MEM_COMMIT ||
    (copMbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
    !(copMbi.Protect & (
        PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
        PAGE_EXECUTE_WRITECOPY)))
{
    OutputDebugStringA(
        "[EternalLightbar] CopUnit memory unreadable\n");
    return;
}

const uintptr_t copRegionStart =
reinterpret_cast<uintptr_t>(copMbi.BaseAddress);

if (copStart < copRegionStart ||
    copStart - copRegionStart >= copMbi.RegionSize ||
    copMbi.RegionSize - (copStart - copRegionStart) <=
    (copEnd - copStart))
{
    OutputDebugStringA(
        "[EternalLightbar] CopUnit fields cross memory boundary\n");
    return;
}

// Verify the CopUnit backlink against the vehicle owner.
const uintptr_t copOwner =
*reinterpret_cast<const uintptr_t*>(copStart);

const uint8_t copState =
*reinterpret_cast<const uint8_t*>(copUnit + 0x1E0);

const uint8_t copFlags =
*reinterpret_cast<const uint8_t*>(copEnd);


{
    MEMORY_BASIC_INFORMATION flagMbi{};

    if (kEnableLightbarPrototype &&
        copOwner == vehicleOwner &&
        vehicleOwner != 0 &&
        VirtualQuery(
            reinterpret_cast<LPCVOID>(copEnd),
            &flagMbi,
            sizeof(flagMbi)) != 0 &&
        flagMbi.State == MEM_COMMIT &&
        !(flagMbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
        (flagMbi.Protect & (
            PAGE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
    {
        // Record the original state before modifying anything.
        gPrototypeVehicleOwner = vehicleOwner;
        gPrototypeCopUnit = copUnit;
        gPrototypeOriginalFlags = copFlags;

        // Preserve all other flag bits.
        auto* flagAddress = reinterpret_cast<uint8_t*>(copEnd);

        *flagAddress = static_cast<uint8_t>(copFlags | 0x04);

        gPrototypeFlagModified = true;


        OutputDebugStringA(
            "[EternalLightbar] PROTOTYPE: scripted-light bit set\n");
    }
}

char copDiagnosticMessage[256]{};

sprintf_s(
    copDiagnosticMessage,
    "[EternalLightbar] CopUnit owner match: %s; "
    "State: 0x%02X; Flags: 0x%02X; "
    "Scripted-light bit: %s\n",
    copOwner == vehicleOwner ? "YES" : "NO",
    static_cast<unsigned int>(copState),
    static_cast<unsigned int>(copFlags),
    (copFlags & 0x04) ? "SET" : "CLEAR"
);

OutputDebugStringA(copDiagnosticMessage);

if (copOwner == vehicleOwner && vehicleOwner != 0)
{
    gLastVehicleOwner = vehicleOwner;

    OutputDebugStringA(
        "[EternalLightbar] Verified vehicle owner cached\n");
}

// === VehicleEffects read-only diagnostic ===
// Expected pointer slot: CopUnit + 0xD0
// Expected state field: VehicleEffects + 0x160

auto IsReadableRange = [](uintptr_t address, size_t bytes) -> bool
    {
        if (address == 0 || bytes == 0 ||
            address > UINTPTR_MAX - (bytes - 1))
            return false;

        uintptr_t current = address;
        const uintptr_t end = address + bytes;

        while (current < end)
        {
            MEMORY_BASIC_INFORMATION mbi{};

            if (VirtualQuery(
                reinterpret_cast<LPCVOID>(current),
                &mbi, sizeof(mbi)) == 0 ||
                mbi.State != MEM_COMMIT ||
                (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
                !(mbi.Protect & (
                    PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                    PAGE_EXECUTE_WRITECOPY)))
                return false;

            const uintptr_t regionStart =
                reinterpret_cast<uintptr_t>(mbi.BaseAddress);

            if (current < regionStart ||
                mbi.RegionSize == 0 ||
                mbi.RegionSize > UINTPTR_MAX - regionStart)
                return false;

            const uintptr_t regionEnd =
                regionStart + mbi.RegionSize;

            if (regionEnd <= current)
                return false;

            current = regionEnd < end ? regionEnd : end;
        }

        return true;
    };

if (copUnit > UINTPTR_MAX - 0xD0 ||
    !IsReadableRange(copUnit + 0xD0, sizeof(uintptr_t)))
{
    OutputDebugStringA(
        "[EternalLightbar] VehicleEffects pointer slot unreadable\n");
    return;
}

const uintptr_t vehicleEffects =
*reinterpret_cast<const uintptr_t*>(copUnit + 0xD0);

char effectsPointerMessage[256]{};

sprintf_s(
    effectsPointerMessage,
    "[EternalLightbar] VehicleEffects pointer: 0x%llX\n",
    static_cast<unsigned long long>(vehicleEffects));

OutputDebugStringA(effectsPointerMessage);

if (vehicleEffects == 0 ||
    vehicleEffects > UINTPTR_MAX - 0x160 ||
    !IsReadableRange(vehicleEffects + 0x160, sizeof(uint32_t)))
{
    OutputDebugStringA(
        "[EternalLightbar] VehicleEffects state unavailable\n");
    return;
}

const uint32_t effectsState =
*reinterpret_cast<const uint32_t*>(vehicleEffects + 0x160);

char effectsStateMessage[256]{};

sprintf_s(
    effectsStateMessage,
    "[EternalLightbar] VehicleEffects state +0x160: %u (0x%08X)\n",
    static_cast<unsigned int>(effectsState),
    static_cast<unsigned int>(effectsState));

OutputDebugStringA(effectsStateMessage);

}

bool InstallHeartbeatHook()
{
    const auto base =
        reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));

    constexpr uintptr_t slotRva = 0x1784BF8;
    constexpr uintptr_t originalRva = 0x412490;

    auto* slot = reinterpret_cast<void**>(base + slotRva);
    void* expected = reinterpret_cast<void*>(base + originalRva);

    MEMORY_BASIC_INFORMATION mbi{};

    if (VirtualQuery(slot, &mbi, sizeof(mbi)) == 0 ||
        mbi.State != MEM_COMMIT ||
        (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
    {
        OutputDebugStringA(
            "[EternalLightbar] Hook aborted: slot not readable\n"
        );
        return false;
    }

    const auto regionStart =
        reinterpret_cast<uintptr_t>(mbi.BaseAddress);

    const auto regionEnd = regionStart + mbi.RegionSize;
    const auto slotAddress = reinterpret_cast<uintptr_t>(slot);

    if (slotAddress < regionStart ||
        slotAddress >= regionEnd ||
        regionEnd - slotAddress < sizeof(void*))
    {
        OutputDebugStringA(
            "[EternalLightbar] Hook aborted: invalid slot boundary\n"
        );
        return false;
    }

    if (*slot != expected)
    {
        OutputDebugStringA(
            "[EternalLightbar] Hook aborted: unexpected original pointer\n"
        );
        return false;
    }

    // Prepare the original function before any pointer replacement.
    InGameOnUpdate::gHook.mOriginal = expected;

    OutputDebugStringA(
        "[EternalLightbar] Original update function prepared\n"
    );

    void* replacement =
        reinterpret_cast<void*>(&InGameOnUpdate::Fn);

    DWORD oldProtect = 0;

    if (!VirtualProtect(
        slot,
        sizeof(void*),
        PAGE_READWRITE,
        &oldProtect))
    {
        OutputDebugStringA(
            "[EternalLightbar] Hook aborted: VirtualProtect failed\n"
        );
        return false;
    }

    void* previous = InterlockedCompareExchangePointer(
        reinterpret_cast<PVOID volatile*>(slot),
        replacement,
        expected
    );

    DWORD unusedProtect = 0;
    BOOL protectionRestored = VirtualProtect(
        slot,
        sizeof(void*),
        oldProtect,
        &unusedProtect
    );

    if (previous != expected)
    {
        OutputDebugStringA(
            "[EternalLightbar] Hook aborted: pointer changed before installation\n"
        );
        return false;
    }

    if (!protectionRestored)
    {
        OutputDebugStringA(
            "[EternalLightbar] WARNING: Hook installed, but "
            "original memory protection could not be restored!\n"
        );

        // The hook is already installed at this point.
        // Do not report it as an uninstalled hook.
    }

    OutputDebugStringA(
        "[EternalLightbar] Atomic pointer replacement succeeded\n"
    );

    OutputDebugStringA(
        "[EternalLightbar] Heartbeat hook installed successfully!\n"
    );

    return true;
}

bool PinEternalLightbarModule()
{
    HMODULE pinnedModule = nullptr;

    BOOL success = GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(
            &PinEternalLightbarModule
            ),
        &pinnedModule
    );

    if (!success)
    {
        OutputDebugStringA(
            "[EternalLightbar] Failed to pin ASI module\n"
        );
        return false;
    }

    OutputDebugStringA(
        "[EternalLightbar] ASI module pinned successfully\n"
    );

    return true;
}

DWORD WINAPI EternalLightbarThread(LPVOID)
{
    OutputDebugStringA(
        "[EternalLightbar] Initialization thread started\n"
    );

    // Keep our ASI loaded while the game references our callback.
    if (!PinEternalLightbarModule())
    {
        OutputDebugStringA(
            "[EternalLightbar] Hook cancelled: module pin failed\n"
        );
        return 1;
    }

    // Install our guarded gameplay update hook.
    if (!InstallHeartbeatHook())
    {
        OutputDebugStringA(
            "[EternalLightbar] Hook installation unsuccessful\n"
        );
        return 1;
    }

    OutputDebugStringA(
        "[EternalLightbar] Heartbeat experiment is active!\n"
    );

    return 0;
}

BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        gEternalLightbarModule = module;

        // We don't need notifications for every thread.
        DisableThreadLibraryCalls(module);

        OutputDebugStringA(
            "[EternalLightbar] DLL attached\n"
        );

        char baseMessage[256]{};

        sprintf_s(
            baseMessage,
            "[EternalLightbar] SDK base: 0x%llX; Windows base: 0x%llX\n",
            static_cast<unsigned long long>(SDK::gBaseAddress),
            static_cast<unsigned long long>(
                reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr))
                )
        );

        OutputDebugStringA(baseMessage);

        // Existing SDK compatibility diagnostic.
        auto address = reinterpret_cast<u32*>(
            SDK_RVA(0x201D59C)
            );

        MEMORY_BASIC_INFORMATION mbi{};

        if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0 ||
            mbi.State != MEM_COMMIT ||
            (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
        {
            OutputDebugStringA(
                "[EternalLightbar] SDK check address not readable\n"
            );
        }
        else
        {
            const auto actual = *address;

            char message[256]{};

            sprintf_s(
                message,
                "[EternalLightbar] Actual value: 0x%08X; "
                "Expected: 0x%08X\n",
                actual,
                0x201E094
            );

            OutputDebugStringA(message);
        }

        // Read-only verification of our Ghidra findings.
        ValidateGameStatePointer();

        // Start our diagnostic worker without waiting for it.
        HANDLE thread = CreateThread(
            nullptr,
            0,
            EternalLightbarThread,
            nullptr,
            0,
            nullptr
        );

        if (thread != nullptr)
        {
            CloseHandle(thread);
        }
        else
        {
            OutputDebugStringA(
                "[EternalLightbar] Failed to create initialization thread\n"
            );
        }
    }

    return TRUE;
}
