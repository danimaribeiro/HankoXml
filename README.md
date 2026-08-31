# XmlsecRb

XML digital signatures (XML-DSig) for Ruby, implemented as a Rust native
extension that calls [libxmlsec1](https://www.aleksey.com/xmlsec/) directly
through hand-written [bindgen](https://github.com/rust-lang/rust-bindgen)
FFI bindings. The Ruby-facing API is built with
[Magnus](https://github.com/matsadler/magnus) and
[rb-sys](https://github.com/oxidize-rb/rb-sys).

This is early scaffolding: the extension currently exposes version checking
and crypto backend init/shutdown as a proof that the bindgen → libxmlsec1
pipeline links and runs correctly. Signing/verifying XML is not implemented
yet.

## Requirements

- Rust toolchain (stable)
- libxmlsec1 development headers, discoverable via `pkg-config`:
  - macOS: `brew install xmlsec1`
  - Debian/Ubuntu: `apt install libxmlsec1-dev pkg-config`

## Installation

Not yet released to RubyGems.org. To use from a Gemfile pointed at this
repo:

```ruby
gem "xmlsec_rb", git: "https://github.com/danimaribeiro/xmlsec_rb"
```

## Usage

```ruby
require "xmlsec_rb"

XmlsecRb.check_version # => true if the linked libxmlsec1 matches the version bindgen ran against
XmlsecRb.init!         # initializes xmlsec + the OpenSSL crypto backend
XmlsecRb.shutdown!     # tears it back down
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then,
run `rake spec` to compile the extension and run the tests. You can also run
`bin/console` for an interactive prompt.

## Contributing

Bug reports and pull requests are welcome on GitHub at
https://github.com/danimaribeiro/xmlsec_rb.

## License

The gem is available as open source under the terms of the
[MIT License](https://opensource.org/licenses/MIT).
