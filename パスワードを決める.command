#!/bin/zsh
cd "$(dirname "$0")"
echo ""
echo "============================================"
echo " 写真アルバムのパスワードを決めます"
echo "============================================"
echo ""
echo " ※ 入力した文字は画面に出ません。そのまま打ってください。"
echo " ※ 会社のPCで写真を開くときに、このパスワードを使います。"
echo ""
echo -n " パスワード： "
read -s PW1
echo ""
echo -n " もう一度　： "
read -s PW2
echo ""
echo ""
if [ -z "$PW1" ]; then echo " 空っぽです。もう一度実行してください。"; echo ""; read -k1 -s; exit 1; fi
if [ "$PW1" != "$PW2" ]; then echo " 2回が一致しませんでした。もう一度実行してください。"; echo ""; read -k1 -s; exit 1; fi
if [ ${#PW1} -lt 6 ]; then echo " 6文字以上にしてください。"; echo ""; read -k1 -s; exit 1; fi
printf %s "$PW1" > .password
chmod 600 .password
echo " 保存しました（${#PW1}文字）。"
echo " このウインドウは閉じてかまいません。"
echo ""
read -k1 -s
