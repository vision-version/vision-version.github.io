import torch
from torch import Tensor

device = torch.device("cuda") if torch.cuda.is_available() else torch.device("cpu")


def min_zero_row(zero_mat: Tensor) -> tuple[Tensor, Tensor]:
    sum_zero_mat = zero_mat.sum(1)
    sum_zero_mat[sum_zero_mat == 0] = 9999

    zero_row = sum_zero_mat.min(0)[1]
    zero_column = zero_mat[zero_row].nonzero()[0]

    zero_mat[zero_row, :] = False
    zero_mat[:, zero_column] = False

    mark_zero = torch.tensor([[zero_row, zero_column]], device=device)
    return zero_mat, mark_zero


def mark_matrix(
    cost_matrix: torch.Tensor,
) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    device = cost_matrix.device
    n = cost_matrix.shape[0]

    zero_mask = cost_matrix == 0
    row_covered = torch.zeros(n, dtype=torch.bool, device=device)
    col_covered = torch.zeros(n, dtype=torch.bool, device=device)
    star_matrix = torch.zeros_like(cost_matrix, dtype=torch.bool, device=device)
    prime_matrix = torch.zeros_like(cost_matrix, dtype=torch.bool, device=device)

    for i in range(n):
        for j in range(n):
            if zero_mask[i, j] and not row_covered[i] and not col_covered[j]:
                star_matrix[i, j] = True
                row_covered[i] = True
                col_covered[j] = True

    row_covered[:] = False
    col_covered[:] = False

    def cover_columns_with_stars():
        for j in range(n):
            if star_matrix[:, j].any():
                col_covered[j] = True

    cover_columns_with_stars()

    while col_covered.sum() < n:
        zeros_uncovered = (
            zero_mask & ~row_covered.unsqueeze(1) & ~col_covered.unsqueeze(0)
        )
        while zeros_uncovered.any():
            row, col = torch.nonzero(zeros_uncovered, as_tuple=False)[0]
            prime_matrix[row, col] = True

            if star_matrix[row].any():
                row_covered[row] = True
                col_covered[star_matrix[row].nonzero(as_tuple=False)[0][0]] = False
            else:

                def find_star_in_col(c):
                    rows = star_matrix[:, c].nonzero(as_tuple=False)
                    return rows[0][0] if rows.numel() > 0 else None

                def find_prime_in_row(r):
                    cols = prime_matrix[r].nonzero(as_tuple=False)
                    return cols[0][0] if cols.numel() > 0 else None

                path = [(row.item(), col.item())]
                done = False
                while not done:
                    star_row = find_star_in_col(path[-1][1])
                    if star_row is not None:
                        path.append((star_row, path[-1][1]))
                        prime_col = find_prime_in_row(star_row)
                        path.append((star_row, prime_col))
                    else:
                        done = True

                for r, c in path:
                    if star_matrix[r, c]:
                        star_matrix[r, c] = False
                    else:
                        star_matrix[r, c] = True

                row_covered[:] = False
                col_covered[:] = False
                prime_matrix[:] = False

                cover_columns_with_stars()
                break
            zeros_uncovered = (
                zero_mask & ~row_covered.unsqueeze(1) & ~col_covered.unsqueeze(0)
            )
        else:
            min_uncovered = cost_matrix[
                ~row_covered.unsqueeze(1) & ~col_covered.unsqueeze(0)
            ].min()
            uncovered_mask = (~row_covered).unsqueeze(1) & (~col_covered).unsqueeze(0)
            cost_matrix[uncovered_mask] -= min_uncovered
            zero_mask = cost_matrix == 0

    assignment_indices = star_matrix.nonzero(as_tuple=False)
    marked_rows = row_covered.nonzero(as_tuple=False).squeeze(1)
    marked_cols = col_covered.nonzero(as_tuple=False).squeeze(1)

    return assignment_indices, marked_rows, marked_cols


def adjust_matrix(mat: Tensor, cover_rows: Tensor, cover_cols: Tensor) -> Tensor:
    bool_cover = torch.zeros_like(mat)
    bool_cover[cover_rows.long()] = True
    bool_cover[:, cover_cols.long()] = True

    non_cover = mat[bool_cover != True]
    min_non_cover = non_cover.min()

    mat[bool_cover != True] = mat[bool_cover != True] - min_non_cover

    double_bool_cover = torch.zeros_like(mat)
    double_bool_cover[cover_rows.long(), cover_cols.long()] = True

    mat[double_bool_cover == True] = mat[double_bool_cover == True] + min_non_cover

    return mat


def hungarian_algorithm(mat: Tensor) -> Tensor:
    dim = mat.shape[0]
    cur_mat = mat

    cur_mat = cur_mat - cur_mat.min(1, keepdim=True)[0]
    cur_mat = cur_mat - cur_mat.min(0, keepdim=True)[0]

    zero_count = 0
    while zero_count < dim:
        ans_pos, marked_rows, marked_cols = mark_matrix(cur_mat)
        zero_count = len(marked_rows) + len(marked_cols)

        if zero_count < dim:
            cur_mat = adjust_matrix(cur_mat, marked_rows, marked_cols)

    return ans_pos


mat = torch.tensor(
    [
        [7, 6, 2, 9, 2],
        [6, 2, 1, 3, 9],
        [5, 6, 8, 9, 5],
        [6, 8, 5, 8, 6],
        [9, 5, 6, 4, 7],
    ],
    device=device,
)

ans_pos = hungarian_algorithm(mat)
print(ans_pos)

res = mat[ans_pos[:, 0].long(), ans_pos[:, 1].long()]
print(res)

print(res.sum())

print("==============")

mat = torch.tensor([[108, 125, 150], [150, 135, 175], [122, 148, 250]], device=device)

ans_pos = hungarian_algorithm(mat)
print(ans_pos)

res = mat[ans_pos[:, 0].long(), ans_pos[:, 1].long()]
print(res)

print(res.sum())

print("==============")

mat = torch.tensor(
    [[1500, 4000, 4500], [2000, 6000, 3500], [2000, 4000, 2500]], device=device
)

ans_pos = hungarian_algorithm(mat)
print(ans_pos)


res = mat[ans_pos[:, 0].long(), ans_pos[:, 1].long()]
print(res)

print(res.sum())

print("==============")

mat = torch.tensor(
    [[5, 9, 3, 6], [8, 7, 8, 2], [6, 10, 12, 7], [3, 10, 8, 6]], device=device
)

ans_pos = hungarian_algorithm(mat)
print(ans_pos)

res = mat[ans_pos[:, 0].long(), ans_pos[:, 1].long()]
print(res)

print(res.sum())
