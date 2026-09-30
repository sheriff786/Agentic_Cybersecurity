"""CLI entry point: `python -m demo_agent.run_demo`"""
from demo_agent.scenarios import scene_benign_passthrough, scene_with_firewall, scene_without_firewall


def main() -> None:
    for scene in (scene_without_firewall, scene_with_firewall, scene_benign_passthrough):
        for line in scene():
            print(line)
        print()


if __name__ == "__main__":
    main()
