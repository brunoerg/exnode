# Tests against bitcoind (tag :interop) need the pinned build in
# vendor/bitcoin/build/bin; without it they are skipped, not failed.
exclude =
  if Exnode.Test.Bitcoind.available?() do
    []
  else
    IO.puts("bitcoind not built (vendor/bitcoin/build/bin): skipping :interop tests")
    [:interop]
  end

ExUnit.start(exclude: exclude)
