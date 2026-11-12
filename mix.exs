# erlang-rocksdb 3.1.2: with no system zstd, the bundled-zstd fallback fails
# (RocksDB's inner configure can't find the zstd it just built), so zstd is
# off unless ERLANG_ROCKSDB_OPTS is set. LZ4 is auto-detected: with
# liblz4-dev installed at build time, exnode compresses the index with LZ4
# (Exnode.Store.KV.compression/0 probes for it). After installing it, rebuild
# with `rm -rf deps/rocksdb/_build && mix deps.compile rocksdb`.
#
# The bundled RocksDB also enables io_uring whenever it finds liburing
# (liburing.h and the library), but the NIF is not linked against it, and its
# WITH_LIBURING option is not passed through: with liburing-dev installed the
# NIF fails to load ("undefined symbol: io_uring_queue_exit"). Link it in that
# case, using the same test RocksDB uses. No spaces: rebar word-splits the
# variable.
liburing? =
  Enum.any?(["/usr/include", "/usr/local/include"], &File.exists?(Path.join(&1, "liburing.h"))) and
    Enum.any?(
      ["/usr/lib", "/usr/lib64", "/usr/local/lib", "/usr/lib/*-linux-gnu"],
      &(Path.wildcard(&1 <> "/liburing.{so,a}") != [])
    )

System.put_env(
  "ERLANG_ROCKSDB_OPTS",
  System.get_env(
    "ERLANG_ROCKSDB_OPTS",
    "-DWITH_ZSTD=OFF" <>
      if(liburing?, do: " -DCMAKE_MODULE_LINKER_FLAGS=-Wl,--no-as-needed,-luring", else: "")
  )
)

defmodule Exnode.MixProject do
  use Mix.Project

  def project do
    [
      app: :exnode,
      version: "0.1.0",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      compilers: [:elixir_make] ++ Mix.compilers(),
      make_targets: ["all"],
      make_clean: ["clean"],
      elixirc_paths: elixirc_paths(Mix.env()),
      test_coverage: test_coverage(),
      deps: deps()
    ]
  end

  # `mix test --cover`: report only (no minimum, so a run below the default
  # 90% does not fail), without the test/support helpers. HTML per module
  # goes to cover/.
  defp test_coverage do
    [
      summary: [threshold: 0],
      ignore_modules: [~r/^Exnode\.Test\./, Exnode.NodeCase, Exnode.InteropCase]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {Exnode.Application, []}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:elixir_make, "~> 0.9", runtime: false},
      {:jason, "~> 1.4"},
      {:bandit, "~> 1.5"},
      {:plug, "~> 1.16"},
      {:rocksdb, "~> 3.1"},
      {:stream_data, "~> 1.1", only: [:dev, :test]}
    ]
  end
end
