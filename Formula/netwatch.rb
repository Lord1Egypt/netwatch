class Netwatch < Formula
  desc "Real-time network diagnostics TUI — like htop for your network"
  homepage "https://github.com/matthart1983/netwatch"
  url "https://github.com/matthart1983/netwatch/archive/refs/tags/v0.15.4.tar.gz"
  sha256 "292cd62aa886ddd8764395a2235f06e615b9d6a555b63c6ea8d857280c8a7ea1"
  license "MIT"
  head "https://github.com/matthart1983/netwatch.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "netwatch", shell_output("#{bin}/netwatch --help 2>&1", 1)
  end
end
