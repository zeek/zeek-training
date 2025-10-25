# Interactive exercises

This directory contains exercises suitable for running with `wr` which is
required for running these exercises, and can be installed from their
[homepage](https://mainmatter.github.io/rust-workshop-runner/).

Once `wr` is installed, one can run tests from the top-level of the repo
checkout by executing

```console
$ wr


Running tests...

        Eternity lies ahead of us, and behind. Your path is not yet finished. 🍂

Do you want to open the next exercise, (01) hands_on_scripting - (00) hello_world? [y/n] y

        Ahead of you lies (01) hands_on_scripting - (00) hello_world

        Open "exercises/01_hands_on_scripting/00_hello_world" in your editor and get started!
        Run `wr` again to compile the exercise and execute its tests.
```

This will guide the user through all exercises, checking them off once the code
in exercises satisfies the check. One can rerun checks for just a single
exercise in the individual exercise directory with `wr check`, e.g.,

```console
$ cd exercises/01_hands_on_scripting/00_hello_world/
$ wr check
        ❌ (01) hands_on_scripting - (00) hello_world

        Meditate on your approach and return. Mountains are merely mountains.



Failed to run:
        cd "../../../exercises/01_hands_on_scripting/00_hello_world" && "btest" "-d" "-v"
Output:
        tests.hello ...
          > zeek --version
          > btest --version
          > zeek %INPUT >output
          > btest-diff output
        ... tests.hello failed
          % 'btest-diff output' failed unexpectedly (exit code 1)
          % cat .diag
          == File ===============================
          Hello world!
          == Diff ===============================
          --- /dev/fd/63        2025-10-25 15:38:41
          +++ /dev/fd/62        2025-10-25 15:38:41
          @@ -1,2 +1 @@
           Hello world!
          -Goodbye world!
          =======================================

          % cat .stderr

        1 of 1 test failed
```

In order to fix this one would look for a place marked `TODO` in the exercise
and tweak it until the test passes.

```console
$ wr check
        🚀 (01) hands_on_scripting - (00) hello_world
```

## Developing exercises

### General test layout

Exercises are organized into chapters and individual exercises. In this example
the top-level chapter folder is `01_hands_on_scripting/` and exercises as child
directories, e.g., `01_hands_on_scripting/00_hello_world/`.

Both chapters and exercises names must have the form

```
<number>_<title>
```

The title must only contain letters, numbers and underscores.

Each test needs to have the following files:

- `.wr.toml`: Test configuration. In particular this contains a
  `[[verification]]` section with a command to run. All examples here run a
  `command` `btest` with some `args`.
- `Cargo.toml`: Empty marker file so folder is recognized as an exercise.

### Adding new exercises

The simplest approach is probably to copy the folder
`01_hands_on_scripting/00_hello_world/` and modify it, e.g.,

```console
$ cp -r 01_hands_on_scripting/00_hello_world/ 01_hands_on_scripting/03_new_exercise
```

Add a `TODO` to guide users to a place to modify. If needed you might also want
to add comments around sections which should not be modified.
