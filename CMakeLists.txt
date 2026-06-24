cmake_minimum_required(VERSION 3.10)
project(ABAC-NDN)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- 1. Recherche des dépendances ---
find_library(PBC_LIBRARY NAMES pbc REQUIRED)
find_library(GMP_LIBRARY NAMES gmp REQUIRED)

# AJOUT : Spécifie les chemins de recherche pour NDN
# HINTS indique où chercher la librairie ndn-cxx.
find_library(NDN_LIBRARY NAMES ndn-cxx 
    HINTS /usr/local/lib64
    REQUIRED
) 

# --- 2. Définition des sources et des en-têtes (Automatisée) ---
file(GLOB ARTIEL_SOURCES
    "src/ABAC-NDN/*.cpp"
    "src/function/*.cpp"
    "src/utils/*.cpp"
)

# Les en-têtes spécifiques à installer (doivent rester listés)
set(ARTIEL_HEADERS
    include/ABAC-NDN/Consumer.hpp
    include/ABAC-NDN/Producer.hpp
    include/ABAC-NDN/Authority.hpp
)

# --- 3. Création de la librairie ---
add_library(ABAC-NDN STATIC ${ARTIEL_SOURCES})

# --- 4. Configuration des chemins d'inclusion (include paths) ---
target_include_directories(ABAC-NDN
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}/include 
        ${CMAKE_CURRENT_SOURCE_DIR}/src/utils
        ${CMAKE_CURRENT_SOURCE_DIR}/src/function
        /usr/local/include/pbc
        # Chemins d'inclusion des dépendances système (NDN-CXX)
        /usr/include 
        /usr/local/include
)

# --- 5. Liaison des dépendances ---
target_link_libraries(ABAC-NDN
    PUBLIC
        ${PBC_LIBRARY}
        ${GMP_LIBRARY}
        ${NDN_LIBRARY} # Liaison de la librairie NDN
)

# --- 6. Règles d'installation ---
install(TARGETS ABAC-NDN
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES ${ARTIEL_HEADERS}
    DESTINATION include/ABAC-NDN
)