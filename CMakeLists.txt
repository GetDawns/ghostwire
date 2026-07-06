cmake_minimum_required(VERSION 3.20)
project(ghostwire VERSION 2.0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(ANRE_CORE_SOURCES
    src/EventCollector.cpp
    src/RelationshipEngine.cpp
    src/NarrativeGenerator.cpp
    src/ThreatScoringEngine.cpp
    src/SignatureChecker.cpp
    src/AttackChainBuilder.cpp
    src/TimelineViewer.cpp
    src/EventDatabase.cpp
    src/ReportWriter.cpp
)

add_library(anre_core STATIC ${ANRE_CORE_SOURCES})
target_include_directories(anre_core PUBLIC include)

if(WIN32)
    # wevtapi: Windows Event Log (Sysmon). iphlpapi: TCP connection table.
    # ws2_32: winsock types + reverse DNS. wintrust/crypt32: Authenticode checks.
    target_link_libraries(anre_core PUBLIC wevtapi iphlpapi ws2_32 wintrust crypt32)
endif()

if(MSVC)
    target_compile_options(anre_core PRIVATE /W4 /permissive-)
else()
    target_compile_options(anre_core PRIVATE -Wall -Wextra -pedantic)
endif()

add_executable(anre src/main.cpp)
target_link_libraries(anre PRIVATE anre_core)

# Stress + fuzz harness (core only, no Qt). Run: ctest, or the exe directly.
enable_testing()
add_executable(ghostwire_stress test/stress.cpp)
target_link_libraries(ghostwire_stress PRIVATE anre_core)
add_test(NAME stress COMMAND ghostwire_stress)

# Qt is optional. Look for it quietly so that machines without Qt installed
# can still configure and build the CLI (anre). The GUI target is only added
# when Qt6 Widgets is actually found below.
find_package(Qt6 QUIET COMPONENTS Widgets Concurrent)

if(Qt6_FOUND)
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)

    qt_add_executable(ghostwire
        src/gui/main_gui.cpp
        src/gui/MainWindow.cpp
        src/gui/WelcomePanel.cpp
        src/gui/RiskGauge.cpp
        src/gui/IncidentPanel.cpp
        src/gui/TimelinePanel.cpp
        src/gui/ProcessGraphPanel.cpp
        src/gui/EventsTablePanel.cpp
        resources/ghostwire.qrc
    )

    target_include_directories(ghostwire PRIVATE include src/gui)
    target_link_libraries(ghostwire PRIVATE anre_core Qt6::Widgets Qt6::Concurrent)

    if(MSVC)
        target_compile_options(ghostwire PRIVATE /W4 /permissive-)
    else()
        target_compile_options(ghostwire PRIVATE -Wall -Wextra -pedantic)
    endif()

    if(WIN32)
        set_target_properties(ghostwire PROPERTIES WIN32_EXECUTABLE TRUE)
    endif()
else()
    message(STATUS "Qt6 not found — building CLI target (anre) only. Install Qt6 Widgets for the GUI.")
endif()
