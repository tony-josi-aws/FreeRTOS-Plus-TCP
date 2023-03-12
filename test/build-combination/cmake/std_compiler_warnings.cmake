function(set_compiler_warnings target_lib_or_exe_name)

  option(WARNINGS_AS_ERRORS "Treat compiler warnings as errors" FALSE)

  set(GCC_WARNINGS
      -Wall   
      -Wextra                     # reasonable and standard
      -Wshadow                    # warn the user if a variable declaration shadows one from a parent context
      -Wcast-align                # warn for potential performance problem casts
      -Wunused                    # warn on anything being unused
      # -Wpedantic                  # warn if non-standard C/C++ is used
      # -Wconversion                # warn on type conversions that may lose data
      # -Wsign-conversion           # warn on sign conversions
      -Wnull-dereference          # warn if a null dereference is detected
      -Wdouble-promotion          # warn if float is implicit promoted to double
      -Wformat=2                  # warn on security issues around functions that format output (ie printf)
      -Wmisleading-indentation    # warn if indentation implies blocks where blocks do not exist
      -Wduplicated-cond           # warn if if / else chain has duplicated conditions
      -Wduplicated-branches       # warn if if / else branches have duplicated code
      -Wlogical-op                # warn about logical operations being used where bitwise were probably wanted
      # -Wuseless-cast              # warn if you perform a cast to the same type
  )

  if(WARNINGS_AS_ERRORS)
    set(GCC_WARNINGS ${GCC_WARNINGS} -Werror)
  endif()

  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(PROJECT_WARNINGS ${GCC_WARNINGS})
  else()
    message(AUTHOR_WARNING "No compiler warnings set for '${CMAKE_CXX_COMPILER_ID}' compiler.")
  endif()

  target_compile_options(${target_lib_or_exe_name} INTERFACE ${PROJECT_WARNINGS})

endfunction()
