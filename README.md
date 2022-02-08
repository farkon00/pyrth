# Porth

Due to certain individuals trying to disrupt the design and development process of the language its reference implementation is closed until it's finished. As soon as I'm comfortable with the design of the language the source code is gonna be open again along with accepting contributions.

In the meantime feel free to do whatever you want with the previous versions of the compiler under MIT license.

To learn how the entire thing has started check out the playlist with development streams: https://www.youtube.com/watch?v=8QP2fDBIxjM&list=PLpM-Dvs8t0VbMZA7wW9aR3EtBqe2kinu4

## How to Access the Last Open Version

The Last Open Version is available at commit c3290073933bb4067339d3bc5550d4d9bf8b12c4. You can access it by cloning this repo and [git-checkout](https://git-scm.com/docs/git-checkout)-ing it:

```console
$ git clone https://gitlab.com/tsoding/porth.git
$ cd porth
$ git checkout c329007
```

## Development Milestones

- [x] Compiled to a native instruction set (only x86_64 for now)
- [x] [Turing-complete](https://gitlab.com/tsoding/porth/-/blob/c3290073933bb4067339d3bc5550d4d9bf8b12c4/examples/rule110.porth)
- [x] Statically typed (the type checking is inspired by [WASM validation](https://binji.github.io/posts/webassembly-type-checking/))
- [x] [Self-hosted](https://en.wikipedia.org/wiki/Self-hosting_(compilers)) (See [./porth.porth](https://gitlab.com/tsoding/porth/-/blob/c3290073933bb4067339d3bc5550d4d9bf8b12c4/porth.porth), it is actually written in itself)
- [ ] More or else close in convenience to C
- [ ] Optimized
- [ ] Crossplatform
