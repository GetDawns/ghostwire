cmake_minimum_required(VERSION 3.20)
project(ghostwire VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(ANRE_CORE_SOURCES
    src/EventCollector.cpp
    src/RelationshipEngine.cpp
    src/NarrativeGenerator.cpp
    src/ThreatScoringEngine.cpp
    src/AttackChainBuilder.cpp
    src/TimelineViewer.cpp
    src/EventDatabase.cpp
)

add_library(anre_core STATIC ${ANRE_CORE_SOURCES})
target_include_directories(anre_core PUBLIC include)

if(WIN32)
    # wevtapi: Windows Event Log (Sysmon). iphlpapi: TCP connection table.
    # ws2_32: winsock types used by the connection table.
    target_link_libraries(anre_core PUBLIC wevtapi iphlpapi ws2_32)
endif()

if(MSVC)
    target_compile_options(anre_core PRIVATE /W4 /permissive-)
else()
    target_compile_options(anre_core PRIVATE -Wall -Wextra -pedantic)
endif()

add_executable(anre src/main.cpp)
target_link_libraries(anre PRIVATE anre_core)

# Qt is optional. Look for it quietly so that machines without Qt installed
# can still configure and build the CLI (anre). The GUI target is only added
# when Qt6 Widgets is actually found below.
find_package(Qt6 QUIET COMPONENTS Widgets)

if(Qt6_FOUND)
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)

    qt_add_executable(ghostwire
        src/gui/main_gui.cpp
        src/gui/MainWindow.cpp
        src/gui/IncidentPanel.cpp
        src/gui/TimelinePanel.cpp
        src/gui/ProcessGraphPanel.cpp
        src/gui/EventsTablePanel.cpp
        resources/ghostwire.qrc
    )

    target_include_directories(ghostwire PRIVATE include src/gui)
    target_link_libraries(ghostwire PRIVATE anre_core Qt6::Widgets)

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
